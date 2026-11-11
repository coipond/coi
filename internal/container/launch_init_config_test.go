package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitAndConfigureContainer_SetsManagedAndInitConfig(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	for _, tc := range []struct {
		name       string
		initConfig []string
		want       string
	}{
		{"no init config", nil, "init img lic-1 --ephemeral -c user.coi.managed=true"},
		{"workspace", []string{"user.coi.workspace=/home/u/my proj"}, "init img lic-1 --ephemeral -c user.coi.managed=true -c user.coi.workspace=/home/u/my proj"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(logPath)
			if err := initAndConfigureContainer("img", "lic-1", "", true, nil, DefaultHardeningPolicy(), tc.initConfig); err != nil {
				t.Fatal(err)
			}
			var got string
			for _, c := range calls(t, logPath) {
				if c = strings.TrimPrefix(c, "--project default "); strings.HasPrefix(c, "init ") {
					got = c
				}
			}
			if got != tc.want {
				t.Errorf("init call = %q, want %q", got, tc.want)
			}
		})
	}
}

// initCalls returns the logged `incus init` calls, project prefix stripped.
func initCalls(t *testing.T, logPath string) []string {
	t.Helper()
	var out []string
	for _, c := range calls(t, logPath) {
		if c = strings.TrimPrefix(c, "--project default "); strings.HasPrefix(c, "init ") {
			out = append(out, c)
		}
	}
	return out
}

func TestManagerLaunch_PassesInitConfig(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	want := "init img mli-1 --ephemeral -c user.coi.managed=true -c user.coi.workspace=/home/u/proj"
	m := &Manager{ContainerName: "mli-1", InitConfig: []string{"user.coi.workspace=/home/u/proj"}}
	for name, launch := range map[string]func() error{
		"LaunchWithPolicy":         func() error { return m.LaunchWithPolicy("img", true, "", DefaultHardeningPolicy()) },
		"LaunchWithPreStartPolicy": func() error { return m.LaunchWithPreStartPolicy("img", true, "", nil, DefaultHardeningPolicy()) },
	} {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(logPath)
			if err := launch(); err != nil {
				t.Fatal(err)
			}
			if got := initCalls(t, logPath); len(got) != 1 || got[0] != want {
				t.Errorf("init calls = %q, want [%q]", got, want)
			}
		})
	}
}

func TestLaunchContainer_RecreateKeepsInitConfig(t *testing.T) {
	origTimeout, origInterval := startSettleTimeout, startSettleInterval
	t.Cleanup(func() { startSettleTimeout, startSettleInterval = origTimeout, origInterval })
	startSettleTimeout, startSettleInterval = time.Second, time.Millisecond

	// The first start fails and Incus deletes the ephemeral container (list
	// is empty), so coi recreates it; the second start succeeds.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	failed := filepath.Join(dir, "failed")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\n" +
		"case \"$*\" in\n  *\"start rli-1\"*) [ -f " + failed + " ] && exit 0; touch " + failed + "; exit 1 ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := launchContainer("img", "rli-1", "", true, nil, DefaultHardeningPolicy(), []string{"user.coi.workspace=/home/u/proj"}); err != nil {
		t.Fatal(err)
	}
	want := "init img rli-1 --ephemeral -c user.coi.managed=true -c user.coi.workspace=/home/u/proj"
	got := initCalls(t, logPath)
	if len(got) != 2 || got[0] != want || got[1] != want {
		t.Errorf("init calls = %q, want the first init and the recreate both %q", got, want)
	}
}
