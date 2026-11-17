package session

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"testing"

	"github.com/coipond/coi/internal/container"
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

// The Incus call count must not grow with the number of linked worktrees:
// their entries go in one MountDisks batch, in a normal repo and in the
// common dir of a worktree checkout.
func TestCommonDir_WorktreeEntriesInOneBatch(t *testing.T) {
	for _, n := range []int{1, 10, 100} {
		ws := t.TempDir()
		mkGitDir(t, ws, ".git")
		for i := range n {
			wt := filepath.Join(ws, ".git", "worktrees", "w"+strconv.Itoa(i))
			if err := os.MkdirAll(wt, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(wt, "commondir"), []byte("../..\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		dev := &batchDevices{}
		if _, err := SetupSecurityMounts(dev, ws, "/workspace", []string{".git/hooks", ".git/config", ".git/commondir"}, false, nil, NestedGitScan{}, false); err != nil {
			t.Fatal(err)
		}
		if len(dev.mounts) != 2 || len(dev.batches) != 1 {
			t.Errorf("workspace n=%d: want 2 single mounts and 1 batch, got %d mounts, %d batches", n, len(dev.mounts), len(dev.batches))
		}

		dev = &batchDevices{}
		if _, err := SetupCommonDirProtection(dev, filepath.Join(ws, ".git"), false, false, nil); err != nil {
			t.Fatal(err)
		}
		if len(dev.mounts) != 0 || len(dev.batches) != 1 {
			t.Errorf("common dir n=%d: want 1 batch, got %d mounts, %d batches", n, len(dev.mounts), len(dev.batches))
		}
	}
}

// incusNameDevices applies the Incus device name rule (at most 64 chars of
// [A-Za-z0-9._-]) and keys devices by name, as one PATCH does.
type incusNameDevices struct {
	recordingDevices
	byName map[string]string
}

var incusDeviceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (d *incusNameDevices) add(name, path string) error {
	if !incusDeviceName.MatchString(name) {
		return fmt.Errorf("invalid device name %q", name)
	}
	d.byName[name] = path
	return nil
}

func (d *incusNameDevices) MountDisk(name, _, path string, _, _ bool) error {
	return d.add(name, path)
}

func (d *incusNameDevices) MountDisks(mounts []container.DiskMount) error {
	for _, m := range mounts {
		if !incusDeviceName.MatchString(m.Name) {
			return fmt.Errorf("invalid device name %q", m.Name)
		}
	}
	for _, m := range mounts {
		_ = d.add(m.Name, m.Path)
	}
	return nil
}

// Linked worktree names are repo-controlled: a long name, a name with "+"
// and names that differ only in dots must each get a valid, distinct device,
// and must not cost the other entries of the batch.
func TestSetupSecurityMounts_WorktreeNamesGiveValidDistinctDevices(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws, ".git")
	mkGitDir(t, ws, ".git/modules/lib")
	names := []string{"feature-branch-with-a-very-long-descriptive-name", "a+b", "v1.2", "v12"}
	for _, n := range names {
		wt := filepath.Join(ws, ".git", "worktrees", n)
		if err := os.MkdirAll(wt, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wt, "commondir"), []byte("../..\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	dev := &incusNameDevices{byName: map[string]string{}}
	if _, err := SetupSecurityMounts(dev, ws, "/workspace", []string{".git/config", ".git/commondir"}, false, nil, NestedGitScan{}, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mounted := map[string]bool{}
	for _, p := range dev.byName {
		mounted[p] = true
	}
	want := []string{"/workspace/.git/commondir", "/workspace/.git/modules/lib/config"}
	for _, n := range names {
		want = append(want, filepath.Join("/workspace/.git/worktrees", n, "commondir"))
	}
	for _, w := range want {
		if !mounted[w] {
			t.Errorf("%s not mounted; devices: %v", w, dev.byName)
		}
	}
}
