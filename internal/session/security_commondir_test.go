package session

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// An absent .git/commondir is materialized with a placeholder git accepts as
// "the git dir itself", and is mounted read-only; an existing linked
// worktree's commondir is protected as it is.
func TestSetupSecurityMounts_CommonDir(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	ws := filepath.Join(dir, "ws")
	gitCmd(t, dir, "init", "-q", ws)
	gitCmd(t, ws, "commit", "-q", "--allow-empty", "-m", "init")
	wt := filepath.Join(dir, "wt")
	gitCmd(t, ws, "worktree", "add", "-q", wt)
	wtCommonDir := filepath.Join(ws, ".git", "worktrees", "wt", "commondir")
	before, err := os.ReadFile(wtCommonDir)
	if err != nil {
		t.Fatal(err)
	}

	rec := &recordingDevices{}
	effective, err := SetupSecurityMounts(rec, ws, "/workspace", []string{".git/config", ".git/commondir"}, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data, err := os.ReadFile(filepath.Join(ws, ".git", "commondir")); err != nil || string(data) != commonDirPlaceholder {
		t.Fatalf(".git/commondir = %q, %v; want %q", data, err, commonDirPlaceholder)
	}
	if after, err := os.ReadFile(wtCommonDir); err != nil || string(after) != string(before) {
		t.Errorf("worktree commondir changed: %q -> %q (%v)", before, after, err)
	}
	wtRel := filepath.Join(".git", "worktrees", "wt", "commondir")
	if !slices.Contains(effective, wtRel) {
		t.Errorf("expected %s in effective paths, got %v", wtRel, effective)
	}
	for _, rel := range []string{".git/commondir", wtRel} {
		path := filepath.Join("/workspace", rel)
		if !slices.ContainsFunc(rec.mounts, func(m mountedDevice) bool { return m.path == path && m.readonly }) {
			t.Errorf("expected a read-only mount at %s, got %v", path, rec.mounts)
		}
	}

	gitDir, err := filepath.EvalSymlinks(filepath.Join(ws, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	if got := gitCmd(t, ws, "rev-parse", "--path-format=absolute", "--git-common-dir"); got != gitDir {
		t.Errorf("git common dir with the placeholder = %q, want %q", got, gitDir)
	}
	gitCmd(t, ws, "status")
	gitCmd(t, ws, "worktree", "add", "-q", filepath.Join(dir, "wt2"))
	gitCmd(t, ws, "worktree", "remove", filepath.Join(dir, "wt2"))
	if got := gitCmd(t, wt, "rev-parse", "--path-format=absolute", "--git-common-dir"); got != gitDir {
		t.Errorf("worktree common dir = %q, want %q", got, gitDir)
	}
	gitCmd(t, wt, "commit", "-q", "--allow-empty", "-m", "wt")
}

// The common dir of a worktree checkout gets a commondir placeholder; a
// linked worktree's commondir is protected only when it exists, since a
// placeholder would point that worktree at its own admin dir.
func TestSetupCommonDirProtection_CommonDir(t *testing.T) {
	common := t.TempDir()
	mkGitDir(t, common, ".")
	for _, wt := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(common, "worktrees", wt), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(common, "worktrees", "a", "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := &recordingDevices{}
	protected, err := SetupCommonDirProtection(rec, common, false, false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	aRel := filepath.Join("worktrees", "a", "commondir")
	bRel := filepath.Join("worktrees", "b", "commondir")
	if !slices.Contains(protected, "commondir") || !slices.Contains(protected, aRel) || slices.Contains(protected, bRel) {
		t.Errorf("protected = %v, want commondir and %s, not %s", protected, aRel, bRel)
	}
	if data, err := os.ReadFile(filepath.Join(common, "commondir")); err != nil || string(data) != commonDirPlaceholder {
		t.Errorf("commondir = %q, %v; want %q", data, err, commonDirPlaceholder)
	}
	if data, err := os.ReadFile(filepath.Join(common, aRel)); err != nil || string(data) != "../..\n" {
		t.Errorf("%s = %q, %v; want it unchanged", aRel, data, err)
	}
	if _, err := os.Lstat(filepath.Join(common, bRel)); !os.IsNotExist(err) {
		t.Errorf("%s must not be created: %v", bRel, err)
	}
	for _, rel := range []string{"commondir", aRel} {
		path := filepath.Join(common, rel)
		if !slices.ContainsFunc(rec.mounts, func(m mountedDevice) bool { return m.path == path && m.readonly }) {
			t.Errorf("expected a read-only mount at %s, got %v", path, rec.mounts)
		}
	}
}
