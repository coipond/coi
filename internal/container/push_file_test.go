package container

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Incus 7.5+ makes a pushed file root-owned unless the push names the owner,
// so PushFile passes the source's UID, GID and mode.
func TestPushFile_PassesSourceOwnerAndMode(t *testing.T) {
	log := fakeIncusScript(t, "exit 0")
	src := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(src, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o775); err != nil {
		t.Fatal(err)
	}

	if err := NewManager("c1").PushFile(src, "opt/script.sh"); err != nil {
		t.Fatalf("PushFile() error = %v", err)
	}
	logged := calls(t, log)
	want := fmt.Sprintf("--project %s file push --uid %d --gid %d --mode 0775 %s c1/opt/script.sh",
		IncusProject, os.Getuid(), os.Getgid(), src)
	if len(logged) != 1 || logged[0] != want {
		t.Errorf("incus calls = %q, want [%q]", logged, want)
	}
}

// A missing source is left to incus to report.
func TestPushFile_MissingSourcePushesPlain(t *testing.T) {
	log := fakeIncusScript(t, "exit 0")
	src := filepath.Join(t.TempDir(), "missing")

	if err := NewManager("c1").PushFile(src, "/opt/x"); err != nil {
		t.Fatalf("PushFile() error = %v", err)
	}
	logged := calls(t, log)
	want := "--project " + IncusProject + " file push " + src + " c1/opt/x"
	if len(logged) != 1 || logged[0] != want {
		t.Errorf("incus calls = %q, want [%q]", logged, want)
	}
}
