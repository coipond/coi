package session

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
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
	nestedConfigWt := filepath.Join(nested, ".git", "worktrees", "nested-wt", "config.worktree")
	if _, err := os.Lstat(nestedConfigWt); !os.IsNotExist(err) {
		t.Fatalf("git created %s (%v); the test needs it absent", nestedConfigWt, err)
	}

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
	if !isRegularFile(nestedConfigWt) {
		t.Errorf("absent %s not materialized", nestedConfigWt)
	}
	for _, wt := range []string{subWt, nestedWt} {
		gitCmd(t, wt, "status")
		gitCmd(t, wt, "commit", "-q", "--allow-empty", "-m", "wt")
	}
}

// An absent config.worktree of a root linked worktree is created and mounted
// read-only in the batch, with and without extensions.worktreeConfig, and git
// still works in the worktree.
func TestSetupSecurityMounts_RootLinkedWorktreeConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	for _, worktreeConfig := range []bool{false, true} {
		t.Run(fmt.Sprintf("worktreeConfig=%v", worktreeConfig), func(t *testing.T) {
			dir := t.TempDir()
			ws := filepath.Join(dir, "ws")
			gitCmd(t, dir, "init", "-q", ws)
			gitCmd(t, ws, "commit", "-q", "--allow-empty", "-m", "init")
			if worktreeConfig {
				gitCmd(t, ws, "config", "extensions.worktreeConfig", "true")
			}
			wt := filepath.Join(dir, "wt")
			gitCmd(t, ws, "worktree", "add", "-q", wt)
			rel := filepath.Join(".git", "worktrees", "wt", "config.worktree")
			if _, err := os.Lstat(filepath.Join(ws, rel)); !os.IsNotExist(err) {
				t.Fatalf("git created %s (%v); the test needs it absent", rel, err)
			}

			dev := &batchDevices{}
			effective, err := SetupSecurityMounts(dev, ws, "/workspace", []string{".git/config"}, false, nil, NestedGitScan{}, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertContainsAll(t, effective, []string{rel})
			if len(dev.batches) != 1 {
				t.Fatalf("want 1 batch, got %d", len(dev.batches))
			}
			path := filepath.Join("/workspace", rel)
			if !slices.ContainsFunc(dev.batches[0], func(m container.DiskMount) bool { return m.Path == path && m.Readonly }) {
				t.Errorf("expected a read-only batched mount at %s", path)
			}
			if data, err := os.ReadFile(filepath.Join(ws, rel)); err != nil || len(data) != 0 {
				t.Errorf("%s = %q, %v; want an empty placeholder", rel, data, err)
			}
			gitCmd(t, wt, "status")
			gitCmd(t, wt, "commit", "-q", "--allow-empty", "-m", "wt")
		})
	}
}

// A symlinked worktrees dir of a nested git dir is not followed out of the
// workspace, and nothing is created through it.
func TestExpandNestedGit_SymlinkedWorktreesDir(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	mkGitDir(t, ws, ".git")
	mkGitDir(t, ws, "nested/.git")
	if err := os.MkdirAll(filepath.Join(outside, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "x", "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "nested", ".git", "worktrees")); err != nil {
		t.Fatal(err)
	}

	for _, p := range expandNestedGit(ws, nil, nil, NestedGitScan{}, false, nil) {
		if strings.Contains(filepath.ToSlash(p), "/worktrees/") {
			t.Errorf("entry through a symlinked worktrees dir: %s", p)
		}
	}
	if _, err := os.Lstat(filepath.Join(outside, "x", "config.worktree")); !os.IsNotExist(err) {
		t.Errorf("config.worktree created outside the workspace: %v", err)
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
	if err := os.MkdirAll(filepath.Join(ws, ".git", "modules", "lib", "worktrees", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	commonDir := filepath.Join(".git", "modules", "lib", "worktrees", "a", "commondir")
	configWt := filepath.Join(".git", "modules", "lib", "worktrees", "a", "config.worktree")
	bCommonDir := filepath.Join(".git", "modules", "lib", "worktrees", "b", "commondir")
	bConfigWt := filepath.Join(".git", "modules", "lib", "worktrees", "b", "config.worktree")

	got := expandNestedGit(ws, nil, nil, NestedGitScan{}, false, nil)
	if !slices.Contains(got, commonDir) || slices.Contains(got, configWt) {
		t.Errorf("got %v, want %s and not the symlinked %s", got, commonDir, configWt)
	}
	if !slices.Contains(got, bConfigWt) || slices.Contains(got, bCommonDir) {
		t.Errorf("got %v, want the materialized %s and not the absent %s", got, bConfigWt, bCommonDir)
	}
	if data, err := os.ReadFile(filepath.Join(ws, bConfigWt)); err != nil || len(data) != 0 {
		t.Errorf("%s = %q, %v; want an empty placeholder", bConfigWt, data, err)
	}
	if _, err := os.Lstat(filepath.Join(ws, bCommonDir)); !os.IsNotExist(err) {
		t.Errorf("%s must not be created: %v", bCommonDir, err)
	}
	sec := &config.SecurityConfig{WritablePaths: []string{commonDir}}
	if got := expandNestedGit(ws, nil, sec, NestedGitScan{}, false, nil); slices.Contains(got, commonDir) {
		t.Errorf("writable_paths opt-out ignored: %v", got)
	}
	again := expandNestedGit(ws, got, nil, NestedGitScan{}, false, nil)
	if len(again) != len(got) {
		t.Errorf("re-expanding must be a no-op, got %v then %v", got, again)
	}
}

// commonDirWarnings runs the coi shell security setup and returns its
// unexpected commondir warnings.
func commonDirWarnings(t *testing.T, ws string, layout *GitWorktreeLayout) []string {
	t.Helper()
	var warnings []string
	opts := SetupOptions{WorkspacePath: ws, Logger: func(msg string) {
		if strings.Contains(msg, "unexpected git commondir") {
			warnings = append(warnings, msg)
		}
	}}
	opts.Security.ProtectedPaths = []string{".git/hooks", ".git/config", ".git/commondir"}
	if _, _, err := applySessionSecurity(&sessionMountRecorder{}, opts, "/workspace", false, layout, false, "c1", NestedGitScan{}); err != nil {
		t.Fatal(err)
	}
	return warnings
}

// commonDirRepo builds a workspace repo with a submodule, a nested repo and a
// linked worktree of each, as git makes them.
func commonDirRepo(t *testing.T) (dir, ws string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir = t.TempDir()
	lib := filepath.Join(dir, "lib")
	ws = filepath.Join(dir, "ws")
	for _, d := range []string{lib, ws} {
		gitCmd(t, dir, "init", "-q", d)
		gitCmd(t, d, "commit", "-q", "--allow-empty", "-m", "init")
	}
	gitCmd(t, ws, "submodule", "add", "-q", lib, "lib")
	nested := filepath.Join(ws, "nested")
	gitCmd(t, ws, "init", "-q", nested)
	gitCmd(t, nested, "commit", "-q", "--allow-empty", "-m", "init")
	gitCmd(t, ws, "worktree", "add", "-q", filepath.Join(dir, "wt"))
	gitCmd(t, filepath.Join(ws, "lib"), "worktree", "add", "-q", filepath.Join(dir, "sub-wt"))
	gitCmd(t, nested, "worktree", "add", "-q", filepath.Join(dir, "nested-wt"))
	return dir, ws
}

// A commondir of the root, a submodule or a nested git dir that names another
// dir is reported with the dir it names; the file is kept as it is.
func TestApplySessionSecurity_UnexpectedCommonDir(t *testing.T) {
	for _, gitDir := range []string{".git", ".git/modules/lib", "nested/.git"} {
		t.Run(gitDir, func(t *testing.T) {
			_, ws := commonDirRepo(t)
			target := filepath.Join(ws, "planted")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(ws, gitDir, "commondir")
			planted := target + "\n"
			if err := os.WriteFile(file, []byte(planted), 0o644); err != nil {
				t.Fatal(err)
			}

			warnings := commonDirWarnings(t, ws, nil)
			want := filepath.Join(gitDir, "commondir") + " -> " + target
			if len(warnings) != 1 || !strings.Contains(warnings[0], want) {
				t.Errorf("warnings = %q, want one naming %q", warnings, want)
			}
			if data, err := os.ReadFile(file); err != nil || string(data) != planted {
				t.Errorf("%s = %q, %v; want it kept as %q", file, data, err, planted)
			}
		})
	}
}

// git-made layouts and a commondir naming its own git dir (also through a
// symlink) give no warning:
// coi's placeholder, linked worktrees of the root, a submodule and a nested
// repo, and a workspace that is a linked worktree.
func TestApplySessionSecurity_NoUnexpectedCommonDir(t *testing.T) {
	dir, ws := commonDirRepo(t)
	if w := commonDirWarnings(t, ws, nil); len(w) != 0 {
		t.Errorf("git-made layout: unexpected warnings %q", w)
	}
	if data, err := os.ReadFile(filepath.Join(ws, ".git", "commondir")); err != nil || string(data) != commonDirPlaceholder {
		t.Fatalf(".git/commondir = %q, %v; want the placeholder", data, err)
	}
	if w := commonDirWarnings(t, ws, nil); len(w) != 0 {
		t.Errorf("second launch: unexpected warnings %q", w)
	}

	sub := filepath.Join(ws, ".git", "modules", "lib")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(ws, link); err != nil {
		t.Fatal(err)
	}
	viaLink := filepath.Join(link, ".git", "modules", "lib")
	for _, self := range []string{".", "./\n", "./\r\n", sub + "\n", viaLink + "\n", "\n"} {
		if err := os.WriteFile(filepath.Join(sub, "commondir"), []byte(self), 0o644); err != nil {
			t.Fatal(err)
		}
		if w := commonDirWarnings(t, ws, nil); len(w) != 0 {
			t.Errorf("commondir %q: unexpected warnings %q", self, w)
		}
	}

	wt := filepath.Join(dir, "wt")
	layout, err := ResolveGitWorktree(wt)
	if err != nil || layout == nil {
		t.Fatalf("ResolveGitWorktree = %v, %v", layout, err)
	}
	if w := commonDirWarnings(t, wt, layout); len(w) != 0 {
		t.Errorf("linked worktree workspace: unexpected warnings %q", w)
	}
}

// The common dir of a worktree checkout is checked too.
func TestApplySessionSecurity_UnexpectedCommonDirInCommonDir(t *testing.T) {
	dir, ws := commonDirRepo(t)
	wt := filepath.Join(dir, "wt")
	layout, err := ResolveGitWorktree(wt)
	if err != nil || layout == nil {
		t.Fatalf("ResolveGitWorktree = %v, %v", layout, err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".git", "commondir"), []byte("../nested/.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	warnings := commonDirWarnings(t, wt, layout)
	want := filepath.Join(layout.CommonDir, "commondir") + " -> " + filepath.Join(layout.CommonDir, "..", "nested", ".git")
	if len(warnings) != 1 || !strings.Contains(warnings[0], filepath.Clean(want)) {
		t.Errorf("warnings = %q, want one naming %q", warnings, filepath.Clean(want))
	}
}

// A commondir that reaches another dir through a symlink and ".." warns with
// the dir git uses: git resolves the symlink before "..".
func TestApplySessionSecurity_UnexpectedCommonDirThroughSymlink(t *testing.T) {
	_, ws := commonDirRepo(t)
	realGit := filepath.Join(ws, "d", "real.git")
	gitCmd(t, ws, "init", "-q", "--bare", realGit)
	if err := os.Mkdir(filepath.Join(realGit, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "d", "real.git", "x"), filepath.Join(ws, ".git", "lnk")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".git", "commondir"), []byte("lnk/..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(realGit)
	if err != nil {
		t.Fatal(err)
	}
	if got := gitCmd(t, ws, "rev-parse", "--path-format=absolute", "--git-common-dir"); got != want {
		t.Fatalf("git common dir = %q, want %q", got, want)
	}

	warnings := commonDirWarnings(t, ws, nil)
	if len(warnings) != 1 || !strings.Contains(warnings[0], ".git/commondir -> "+want) {
		t.Errorf("warnings = %q, want one naming %q", warnings, want)
	}
}

// A commondir that names a dir that does not exist yet warns with the path as
// written: git uses it once the dir is created.
func TestApplySessionSecurity_UnexpectedCommonDirMissingTarget(t *testing.T) {
	_, ws := commonDirRepo(t)
	if err := os.WriteFile(filepath.Join(ws, ".git", "commondir"), []byte("../planted-later\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	warnings := commonDirWarnings(t, ws, nil)
	want := ".git/commondir -> " + filepath.Join(ws, ".git") + "/../planted-later"
	if len(warnings) != 1 || !strings.Contains(warnings[0], want) {
		t.Errorf("warnings = %q, want one naming %q", warnings, want)
	}
}

// A linked worktree config.worktree placeholder is not created through a
// symlinked .git.
func TestExpandGitWorktreeProtectedPaths_SymlinkedGitDir(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "worktrees", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, ".git")); err != nil {
		t.Fatal(err)
	}

	if got := ExpandGitWorktreeProtectedPaths(ws, nil, nil); len(got) != 0 {
		t.Errorf("entries through a symlinked .git: %v", got)
	}
	if _, err := os.Lstat(filepath.Join(outside, "worktrees", "x", "config.worktree")); !os.IsNotExist(err) {
		t.Errorf("config.worktree created outside the workspace: %v", err)
	}
}

// The submodule git dirs of a worktree checkout's common dir (modules/**,
// nested modules included) get the entries the workspace's own .git/modules
// git dirs get, in the one batch.
func TestSetupCommonDirProtection_SubmoduleGitDirs(t *testing.T) {
	common := t.TempDir()
	mkGitDir(t, common, ".")
	mkGitDir(t, common, "modules/sub")
	mkGitDir(t, common, "modules/a")
	mkGitDir(t, common, "modules/a/modules/b")
	wt := filepath.Join(common, "modules", "sub", "worktrees", "w")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dev := &batchDevices{}
	protected, err := SetupCommonDirProtection(dev, common, false, false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var want []string
	for _, gitDir := range []string{"modules/sub", "modules/a", "modules/a/modules/b"} {
		for _, entry := range nestedGitDirEntries {
			want = append(want, filepath.Join(gitDir, entry))
		}
	}
	want = append(want, "modules/sub/worktrees/w/config.worktree", "modules/sub/worktrees/w/commondir")
	for _, rel := range want {
		if !slices.Contains(protected, rel) {
			t.Errorf("%s not protected; got %v", rel, protected)
		}
		path := filepath.Join(common, rel)
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s not materialized: %v", rel, err)
		}
	}
	if len(dev.mounts) != 0 || len(dev.batches) != 1 {
		t.Fatalf("want 1 batch, got %d mounts, %d batches", len(dev.mounts), len(dev.batches))
	}
	for _, rel := range want {
		path := filepath.Join(common, rel)
		if !slices.ContainsFunc(dev.batches[0], func(m container.DiskMount) bool { return m.Path == path && m.Readonly }) {
			t.Errorf("expected a read-only mount at %s", path)
		}
	}
	if data, err := os.ReadFile(filepath.Join(common, "modules", "sub", "commondir")); err != nil || string(data) != commonDirPlaceholder {
		t.Errorf("modules/sub/commondir = %q, %v; want %q", data, err, commonDirPlaceholder)
	}
}

// writable_hooks, writable_paths and disable_protection apply to the
// submodule git dirs of a common dir; a symlinked modules dir or submodule
// git dir is skipped and nothing is created through it.
func TestSetupCommonDirProtection_SubmoduleGitDirOptOutsAndSymlinks(t *testing.T) {
	common := t.TempDir()
	mkGitDir(t, common, ".")
	mkGitDir(t, common, "modules/sub")
	outside := t.TempDir()
	mkGitDir(t, outside, "linked")
	if err := os.Symlink(filepath.Join(outside, "linked"), filepath.Join(common, "modules", "linked")); err != nil {
		t.Fatal(err)
	}
	mkGitDir(t, outside, "mods/x")
	mkGitDir(t, common, "modules/sub2")
	if err := os.Symlink(filepath.Join(outside, "mods"), filepath.Join(common, "modules", "sub2", "modules")); err != nil {
		t.Fatal(err)
	}

	sec := &config.SecurityConfig{WritablePaths: []string{"modules/sub/config"}}
	protected, err := SetupCommonDirProtection(&batchDevices{}, common, false, true, sec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, rel := range []string{"modules/sub/hooks", "modules/sub/config"} {
		if slices.Contains(protected, rel) {
			t.Errorf("%s must stay writable; got %v", rel, protected)
		}
	}
	if !slices.Contains(protected, "modules/sub/info/attributes") {
		t.Errorf("modules/sub/info/attributes not protected; got %v", protected)
	}
	for _, p := range protected {
		if strings.HasPrefix(p, "modules/linked/") || strings.HasPrefix(p, "modules/sub2/modules/") {
			t.Errorf("%s is below a symlink; got %v", p, protected)
		}
	}
	for _, rel := range []string{"linked/config.worktree", "linked/commondir", "mods/x/config.worktree", "mods/x/commondir"} {
		if _, err := os.Lstat(filepath.Join(outside, rel)); !os.IsNotExist(err) {
			t.Errorf("%s created through a symlink: %v", rel, err)
		}
	}

	disabled := &config.SecurityConfig{DisableProtection: true}
	if got, err := SetupCommonDirProtection(&batchDevices{}, common, false, false, disabled); err != nil || len(got) != 0 {
		t.Errorf("disable_protection: got %v, %v; want nothing", got, err)
	}
}
