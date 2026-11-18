package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// An empty destination is the container root, never an index panic.
func TestPushFile_EmptyDestination(t *testing.T) {
	log := fakeIncusScript(t, "exit 0")
	src := filepath.Join(t.TempDir(), "missing")

	if err := NewManager("c1").PushFile(src, ""); err != nil {
		t.Fatalf("PushFile() error = %v", err)
	}
	if err := NewManager("c1").PushFileWithOwner(src, "", 0, 0, "0644"); err != nil {
		t.Fatalf("PushFileWithOwner() error = %v", err)
	}
	logged := calls(t, log)
	if len(logged) != 2 || !strings.HasSuffix(logged[0], " c1/") || !strings.HasSuffix(logged[1], " c1/") {
		t.Errorf("incus calls = %q, want two pushes to c1/", logged)
	}
}
