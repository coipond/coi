package container

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// AppliedState reads disks (a pool volume and the root disk included), the
// environment.* names (never values) and security.nesting from the expanded
// config.
func TestAppliedState(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
case "$*" in
  *"config show --expanded c2"*) printf 'config:\n  security.nesting: "false"\n  environment.GIT_AUTHOR_NAME: Jane\n  environment.ANTHROPIC_MODEL: opus\n  user.coi.git_env_keys: GIT_AUTHOR_NAME\ndevices:\n  root:\n    path: /\n    pool: default\n    type: disk\n  cache:\n    path: /cache\n    pool: default\n    source: cache\n    type: disk\n  eth0:\n    type: nic\n' ;;
  *) echo "Error: Instance not found" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	invalidateConfigCache()
	t.Cleanup(invalidateConfigCache)

	st, err := (&Manager{ContainerName: "c2"}).AppliedState()
	if err != nil {
		t.Fatal(err)
	}
	if st.Nesting {
		t.Error("nesting is off")
	}
	if want := []string{"ANTHROPIC_MODEL", "GIT_AUTHOR_NAME"}; !reflect.DeepEqual(st.EnvNames, want) {
		t.Errorf("env names = %v, want %v", st.EnvNames, want)
	}
	want := map[string]DiskDevice{
		"root":  {Path: "/", Pool: "default"},
		"cache": {Source: "cache", Path: "/cache", Pool: "default"},
	}
	if !reflect.DeepEqual(st.Disks, want) {
		t.Errorf("disks = %+v, want %+v", st.Disks, want)
	}

	if _, err := (&Manager{ContainerName: "missing"}).AppliedState(); err == nil {
		t.Error("an unreadable config should be an error")
	}
}
