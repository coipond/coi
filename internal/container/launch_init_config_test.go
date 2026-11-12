package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// incusCalls returns the logged incus calls, project prefix stripped.
func incusCalls(t *testing.T, logPath string) []string {
	t.Helper()
	out := calls(t, logPath)
	for i, c := range out {
		out[i] = strings.TrimPrefix(c, "--project default ")
	}
	return out
}

// initCalls returns the logged `incus init` calls, project prefix stripped.
func initCalls(t *testing.T, logPath string) []string {
	t.Helper()
	var out []string
	for _, c := range incusCalls(t, logPath) {
		if strings.HasPrefix(c, "init ") {
			out = append(out, c)
		}
	}
	return out
}

// defaultPolicyInit is the init argv tail of DefaultHardeningPolicy.
var defaultPolicyInit = " " + strings.Join(InitConfigArgs(DefaultHardeningPolicy()), " ")

func TestInitAndConfigureContainer_SetsManagedAndInitConfig(t *testing.T) {
	logPath := fakeIncusScript(t, "exit 0")

	for _, tc := range []struct {
		name       string
		initConfig []string
		want       string
	}{
		{"no init config", nil, "init img lic-1 --ephemeral -c user.coi.managed=true" + defaultPolicyInit},
		{"workspace", []string{"user.coi.workspace=/home/u/my proj"}, "init img lic-1 --ephemeral -c user.coi.managed=true -c user.coi.workspace=/home/u/my proj" + defaultPolicyInit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(logPath)
			if err := initAndConfigureContainer("img", "lic-1", "", true, nil, DefaultHardeningPolicy(), tc.initConfig); err != nil {
				t.Fatal(err)
			}
			if got := initCalls(t, logPath); len(got) != 1 || got[0] != tc.want {
				t.Errorf("init calls = %q, want [%q]", got, tc.want)
			}
		})
	}
}

// The kernel-surface policy and the guest API go in the `incus init` call;
// no `config set` runs before preStart.
func TestInitAndConfigureContainer_SettingsAtInit(t *testing.T) {
	logPath := fakeIncusScript(t, "exit 0")
	if err := initAndConfigureContainer("img", "c1", "pool1", true, nil, HardeningPolicy{}, nil); err != nil {
		t.Fatal(err)
	}
	got := incusCalls(t, logPath)
	if len(got) == 0 || got[0] != "init img c1 --ephemeral -s pool1 -c user.coi.managed=true -c security.guestapi=false" {
		t.Fatalf("first call = %q", got)
	}
	for _, c := range got[1:] {
		if strings.HasPrefix(c, "config set") || strings.HasPrefix(c, "init") {
			t.Errorf("unexpected write after init: %q", c)
		}
	}
}

func TestManagerLaunch_PassesInitConfig(t *testing.T) {
	logPath := fakeIncusScript(t, "exit 0")

	want := "init img mli-1 --ephemeral -c user.coi.managed=true -c user.coi.workspace=/home/u/proj" + defaultPolicyInit
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
	failed := filepath.Join(t.TempDir(), "failed")
	logPath := fakeIncusScript(t, "case \"$*\" in\n  *\"start rli-1\"*) [ -f "+failed+" ] && exit 0; touch "+failed+"; exit 1 ;;\nesac\nexit 0")

	if err := launchContainer("img", "rli-1", "", true, nil, DefaultHardeningPolicy(), []string{"user.coi.workspace=/home/u/proj"}); err != nil {
		t.Fatal(err)
	}
	want := "init img rli-1 --ephemeral -c user.coi.managed=true -c user.coi.workspace=/home/u/proj" + defaultPolicyInit
	got := initCalls(t, logPath)
	if len(got) != 2 || got[0] != want || got[1] != want {
		t.Errorf("init calls = %q, want the first init and the recreate both %q", got, want)
	}
}
