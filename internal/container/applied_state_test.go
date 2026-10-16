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
  *"config show --expanded c2"*) printf 'config:\n  security.nesting: "false"\n  limits.cpu: "2"\n  limits.cpu.allowance: 50%%\n  limits.memory: 4GiB\n  environment.GIT_AUTHOR_NAME: Jane\n  environment.ANTHROPIC_MODEL: opus\n  user.coi.git_env_keys: GIT_AUTHOR_NAME\ndevices:\n  root:\n    path: /\n    pool: default\n    limits.read: 10MB\n    limits.disk.priority: "5"\n    type: disk\n  cache:\n    path: /cache\n    pool: default\n    source: cache\n    type: disk\n  eth0:\n    type: nic\n' ;;
  *"config show --expanded c3"*) printf 'config:\n  security.nesting: "true"\n  security.syscalls.deny: |-\n    bpf errno 1\n    keyctl errno 1\ndevices: {}\n' ;;
  *"config show c3"*) printf 'config:\n  user.x: "y"\ndevices: {}\n' ;;
  *"config show --expanded c4"*) printf 'config:\n  security.nesting: "true"\ndevices: {}\n' ;;
  *"config show c4"*) printf 'config:\n  security.nesting: "true"\ndevices: {}\n' ;;
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
	wantLimits := map[string]string{"limits.cpu": "2", "limits.cpu.allowance": "50%", "limits.memory": "4GiB", "root.limits.read": "10MB", "root.limits.disk.priority": "5"}
	if !reflect.DeepEqual(st.Limits, wantLimits) {
		t.Errorf("limits = %v, want %v", st.Limits, wantLimits)
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

	// Nesting set only in the expanded config comes from a profile; set on
	// the instance itself, it doesn't; an unreadable config is unknown.
	if st.KernelSurfaceDenied || st.RootPool != "default" {
		t.Errorf("c2: denied %v, root pool %q", st.KernelSurfaceDenied, st.RootPool)
	}
	if st, err := (&Manager{ContainerName: "c3"}).AppliedState(); err != nil || !st.KernelSurfaceDenied {
		t.Errorf("kernel-surface denies not detected: %+v, %v", st, err)
	}
	if set, ok := (&Manager{ContainerName: "c3"}).NestingSetLocally(); set || !ok {
		t.Errorf("profile nesting: set %v ok %v", set, ok)
	}
	if set, ok := (&Manager{ContainerName: "c4"}).NestingSetLocally(); !set || !ok {
		t.Errorf("own nesting: set %v ok %v", set, ok)
	}
	if _, ok := (&Manager{ContainerName: "missing"}).NestingSetLocally(); ok {
		t.Error("an unreadable config should not be ok")
	}

	if _, err := (&Manager{ContainerName: "missing"}).AppliedState(); err == nil {
		t.Error("an unreadable config should be an error")
	}
}
