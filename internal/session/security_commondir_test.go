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

	"github.com/coipond/coi/internal/config"
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

// The linked worktree entries of a submodule git dir and of a nested repo are
// mounted read-only in the batch, and git still works in those worktrees.
func TestSetupSecurityMounts_NestedLinkedWorktrees(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	lib := filepath.Join(dir, "lib")
	ws := filepath.Join(dir, "ws")
	for _, d := range []string{lib, ws} {
		gitCmd(t, dir, "init", "-q", d)
		gitCmd(t, d, "commit", "-q", "--allow-empty", "-m", "init")
	}
	gitCmd(t, ws, "submodule", "add", "-q", lib, "lib")
	nested := filepath.Join(ws, "nested")
	gitCmd(t, ws, "init", "-q", nested)
	gitCmd(t, nested, "commit", "-q", "--allow-empty", "-m", "init")
	subWt := filepath.Join(dir, "sub-wt")
	nestedWt := filepath.Join(dir, "nested-wt")
	gitCmd(t, filepath.Join(ws, "lib"), "worktree", "add", "-q", subWt)
	gitCmd(t, nested, "worktree", "add", "-q", nestedWt)
	for _, d := range []string{filepath.Join(ws, ".git", "modules", "lib"), filepath.Join(nested, ".git")} {
		gitCmd(t, d, "config", "extensions.worktreeConfig", "true")
	}
	gitCmd(t, subWt, "config", "--worktree", "core.bare", "false")
	gitCmd(t, nestedWt, "config", "--worktree", "core.bare", "false")

	var want []string
	for _, gitDir := range []string{".git/modules/lib/worktrees/sub-wt", "nested/.git/worktrees/nested-wt"} {
		want = append(want, filepath.Join(gitDir, "commondir"), filepath.Join(gitDir, "config.worktree"))
	}
	dev := &batchDevices{}
	effective, err := SetupSecurityMounts(dev, ws, "/workspace", []string{".git/config"}, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContainsAll(t, effective, want)
	if len(dev.batches) != 1 {
		t.Fatalf("want 1 batch, got %d", len(dev.batches))
	}
	for _, rel := range want {
		path := filepath.Join("/workspace", rel)
		if !slices.ContainsFunc(dev.batches[0], func(m container.DiskMount) bool { return m.Path == path && m.Readonly }) {
			t.Errorf("expected a read-only batched mount at %s", path)
		}
	}
	for _, wt := range []string{subWt, nestedWt} {
		gitCmd(t, wt, "status")
		gitCmd(t, wt, "commit", "-q", "--allow-empty", "-m", "wt")
	}
}

// A writable_paths opt-out and a symlinked entry are honored for nested
// linked worktrees as for the root ones.
func TestExpandNestedGit_LinkedWorktreeOptOutsAndSymlinks(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws, ".git")
	mkGitDir(t, ws, ".git/modules/lib")
	wt := filepath.Join(ws, ".git", "modules", "lib", "worktrees", "a")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ws, "elsewhere"), filepath.Join(wt, "config.worktree")); err != nil {
		t.Fatal(err)
	}
	commonDir := filepath.Join(".git", "modules", "lib", "worktrees", "a", "commondir")
	configWt := filepath.Join(".git", "modules", "lib", "worktrees", "a", "config.worktree")

	got := expandNestedGit(ws, nil, nil, NestedGitScan{}, false)
	if !slices.Contains(got, commonDir) || slices.Contains(got, configWt) {
		t.Errorf("got %v, want %s and not the symlinked %s", got, commonDir, configWt)
	}
	sec := &config.SecurityConfig{WritablePaths: []string{commonDir}}
	if got := expandNestedGit(ws, nil, sec, NestedGitScan{}, false); slices.Contains(got, commonDir) {
		t.Errorf("writable_paths opt-out ignored: %v", got)
	}
	again := expandNestedGit(ws, got, nil, NestedGitScan{}, false)
	if len(again) != len(got) {
		t.Errorf("re-expanding must be a no-op, got %v then %v", got, again)
	}
}
