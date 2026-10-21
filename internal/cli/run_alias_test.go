package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/alias"
)

func TestApplyContainerAlias_KeepsSavedProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	reg, err := alias.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("proj", "/ws", "pa"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}

	if err := applyContainerAlias("proj", "coi-test-1", "/ws"); err != nil {
		t.Fatalf("applyContainerAlias: %v", err)
	}

	reg, err = alias.Load()
	if err != nil {
		t.Fatal(err)
	}
	if entry := reg.Lookup("proj"); entry == nil || entry.Workspace != "/ws" || entry.Profile != "pa" {
		t.Errorf("coi run must keep the profile coi shell saved, got %+v", entry)
	}
}
