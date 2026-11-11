package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
