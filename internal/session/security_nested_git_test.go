package session

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// mkGitDir creates a minimal git dir (HEAD, config, hooks, info) at rel.
func mkGitDir(t *testing.T, root, rel string) {
	t.Helper()
	dir := filepath.Join(root, rel)
	for _, d := range []string{"hooks", "info"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"HEAD", "config"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func gitDirEntries(gitDir string) []string {
	return []string{
		filepath.Join(gitDir, "hooks"),
		filepath.Join(gitDir, "config"),
		filepath.Join(gitDir, "config.worktree"),
		filepath.Join(gitDir, "info", "attributes"),
	}
}

func assertContainsAll(t *testing.T, got, want []string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("expected %q in %v", w, got)
		}
	}
}

func TestExpandNestedGit_Submodules(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	mkGitDir(t, tmp, ".git/modules/lib")
	mkGitDir(t, tmp, ".git/modules/lib/modules/inner")
	mkGitDir(t, tmp, ".git/modules/vendor/github.com/x/y")
	if err := os.MkdirAll(filepath.Join(tmp, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "lib", ".git"), []byte("gitdir: ../.git/modules/lib\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := expandNestedGit(tmp, []string{".git/config"}, nil, NestedGitScan{}, false)

	var want []string
	want = append(want, gitDirEntries(".git/modules/lib")...)
	want = append(want, gitDirEntries(".git/modules/lib/modules/inner")...)
	want = append(want, gitDirEntries(".git/modules/vendor/github.com/x/y")...)
	want = append(want, filepath.Join("lib", ".git"))
	assertContainsAll(t, out, want)
	if len(out) != 1+len(want) {
		t.Errorf("expected exactly %d added paths, got %v", len(want), out)
	}
	for _, rel := range []string{"config.worktree", "info/attributes"} {
		if _, err := os.Lstat(filepath.Join(tmp, ".git/modules/lib", rel)); err != nil {
			t.Errorf("expected %s placeholder to be materialized: %v", rel, err)
		}
	}
}

func TestExpandNestedGit_NestedRepoAndDepth(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	mkGitDir(t, tmp, "sub/.git")
	mkGitDir(t, tmp, "sub/.git/modules/m")
	mkGitDir(t, tmp, "a/b/c/.git")
	mkGitDir(t, tmp, "a/b/c/d/.git") // below nestedGitSearchDepth
	if err := os.RemoveAll(filepath.Join(tmp, "sub/.git/hooks")); err != nil {
		t.Fatal(err)
	}

	out := expandNestedGit(tmp, nil, nil, NestedGitScan{}, false)

	var want []string
	want = append(want, gitDirEntries("sub/.git")...)
	want = append(want, gitDirEntries("sub/.git/modules/m")...)
	want = append(want, gitDirEntries("a/b/c/.git")...)
	assertContainsAll(t, out, want)
	if len(out) != len(want) {
		t.Errorf("expected exactly %v, got %v", want, out)
	}
	for _, p := range out {
		if strings.HasPrefix(p, ".git/") || strings.HasPrefix(p, "a/b/c/d/") {
			t.Errorf("unexpected path %q (root defaults or beyond depth bound)", p)
		}
	}
	if !isRealDir(filepath.Join(tmp, "sub/.git/hooks")) {
		t.Error("expected missing nested hooks dir to be materialized")
	}
}

func TestExpandNestedGit_OptOutsAndSymlinks(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	mkGitDir(t, tmp, ".git/modules/lib")
	hooks := filepath.Join(".git", "modules", "lib", "hooks")

	sec := &config.SecurityConfig{DisableProtection: true}
	if out := expandNestedGit(tmp, nil, sec, NestedGitScan{}, false); len(out) != 0 {
		t.Errorf("disable_protection should suppress expansion, got %v", out)
	}

	sec = &config.SecurityConfig{WritablePaths: []string{hooks}}
	if out := expandNestedGit(tmp, nil, sec, NestedGitScan{}, false); slices.Contains(out, hooks) {
		t.Errorf("writable_paths entry %q should be excluded, got %v", hooks, out)
	}

	expanded := expandNestedGit(tmp, nil, nil, NestedGitScan{}, false)
	if again := expandNestedGit(tmp, expanded, nil, NestedGitScan{}, false); len(again) != len(expanded) {
		t.Errorf("re-expanding must be a no-op, got %v then %v", expanded, again)
	}

	if err := os.RemoveAll(filepath.Join(tmp, hooks)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(tmp, hooks)); err != nil {
		t.Fatal(err)
	}
	if out := expandNestedGit(tmp, nil, nil, NestedGitScan{}, false); slices.Contains(out, hooks) {
		t.Errorf("symlinked hooks must not be added, got %v", out)
	}

	// A symlinked modules dir is not followed.
	linked := t.TempDir()
	mkGitDir(t, linked, ".git")
	mkGitDir(t, tmp, "elsewhere/x")
	if err := os.Symlink(filepath.Join(tmp, "elsewhere"), filepath.Join(linked, ".git", "modules")); err != nil {
		t.Fatal(err)
	}
	if out := expandNestedGit(linked, nil, nil, NestedGitScan{}, false); len(out) != 0 {
		t.Errorf("symlinked modules dir must not be followed, got %v", out)
	}
}

// A real submodule checkout: its git dir under .git/modules and its .git file
// are mounted read-only, their parent dirs pinned, with collision-free device
// names.
func TestSetupSecurityMounts_ProtectsRealSubmodule(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	tmp := t.TempDir()
	lib := filepath.Join(tmp, "lib")
	ws := filepath.Join(tmp, "ws")
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "protocol.file.allow=always", "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	for _, d := range []string{lib, ws} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		git(d, "init", "-q")
		git(d, "commit", "-q", "--allow-empty", "-m", "init")
	}
	git(ws, "submodule", "add", "-q", lib, "lib")

	rec := &recordingDevices{}
	effective, err := SetupSecurityMounts(rec, ws, "/workspace", nil, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := append(gitDirEntries(".git/modules/lib"), filepath.Join("lib", ".git"))
	assertContainsAll(t, effective, want)

	names := map[string]bool{}
	for _, m := range rec.mounts {
		if m.readonly == strings.HasPrefix(m.name, pinDevicePrefix) {
			t.Errorf("mount %s (%s): only parent pins are read-write", m.path, m.name)
		}
		if names[m.name] {
			t.Errorf("duplicate device name %s", m.name)
		}
		names[m.name] = true
	}
	for _, w := range append(want, ".git", ".git/modules", ".git/modules/lib", "lib") {
		found := false
		for _, m := range rec.mounts {
			if m.path == filepath.Join("/workspace", w) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q to be mounted, got %v", w, rec.mounts)
		}
	}
}

func TestPathToDeviceName_NestedGitHashed(t *testing.T) {
	a := pathToDeviceName("a-b/.git/hooks")
	b := pathToDeviceName("a/b/.git/hooks")
	if a == b {
		t.Errorf("nested git device names collide: %s", a)
	}
	for _, n := range []string{a, b, pathToDeviceName(".git/modules/lib/config")} {
		if !strings.HasPrefix(n, protectDevicePrefix) || len(n) != len(protectDevicePrefix)+16 {
			t.Errorf("expected hashed protect- name, got %q", n)
		}
	}
	if got := pathToDeviceName(".git/hooks"); got != "protect-git-hooks" {
		t.Errorf("root default name changed: %q", got)
	}
}

// batchDevices is recordingDevices plus MountDisks, counting batch calls.
type batchDevices struct {
	recordingDevices
	batches [][]container.DiskMount
}

func (b *batchDevices) MountDisks(mounts []container.DiskMount) error {
	b.batches = append(b.batches, mounts)
	return nil
}

// The Incus call count must not grow with the number of submodules: the
// nested entries and the parent pins go in one MountDisks batch.
func TestSetupSecurityMounts_NestedGitInOneBatch(t *testing.T) {
	for _, n := range []int{1, 10, 100} {
		tmp := t.TempDir()
		mkGitDir(t, tmp, ".git")
		for i := range n {
			mkGitDir(t, tmp, filepath.Join(".git", "modules", "m"+strconv.Itoa(i)))
		}
		dev := &batchDevices{}
		if _, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{".git/hooks", ".git/config"}, false, nil, NestedGitScan{}, false); err != nil {
			t.Fatal(err)
		}
		// Per submodule: 4 entries plus pins of its git dir and info/; plus
		// pins of .git and .git/modules.
		if len(dev.mounts) != 2 || len(dev.batches) != 1 || len(dev.batches[0]) != 6*n+2 {
			t.Errorf("n=%d: want 2 single mounts and 1 batch of %d, got %d mounts, batches %d", n, 6*n+2, len(dev.mounts), len(dev.batches))
		}
	}
}

// A scan started early (Setup) gives the same mounts as one run at mount time.
func TestSetupSecurityMounts_PrefetchedScan(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	mkGitDir(t, tmp, ".git/modules/lib")
	mkGitDir(t, tmp, "sub/.git")

	sync, err := SetupSecurityMounts(&recordingDevices{}, tmp, "/workspace", nil, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := SetupSecurityMounts(&recordingDevices{}, tmp, "/workspace", nil, false, nil, StartNestedGitScan(tmp), false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sync, pre) || len(pre) != 8 {
		t.Errorf("prefetched scan %v differs from sync scan %v", pre, sync)
	}
}

// disable_protection writes nothing, even with a scan already done.
func TestExpandNestedGit_DisabledMaterializesNothing(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	mkGitDir(t, tmp, ".git/modules/lib")
	scan := StartNestedGitScan(tmp)
	sec := &config.SecurityConfig{DisableProtection: true}
	if out := expandNestedGit(tmp, nil, sec, scan, false); len(out) != 0 {
		t.Errorf("want no paths, got %v", out)
	}
	if _, err := os.Lstat(filepath.Join(tmp, ".git/modules/lib/config.worktree")); !os.IsNotExist(err) {
		t.Errorf("placeholder must not be created when protection is disabled: %v", err)
	}
}

// SetupSecurityMounts uses a scan of the same workspace and ignores
// one of another workspace (that one is rescanned at mount time).
func TestSetupSecurityMounts(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws, ".git")
	mkGitDir(t, ws, ".git/modules/lib")
	other := t.TempDir()
	mkGitDir(t, other, ".git")

	want := gitDirEntries(".git/modules/lib")
	for name, scan := range map[string]NestedGitScan{
		"same workspace":  StartNestedGitScan(ws),
		"other workspace": StartNestedGitScan(other),
		"zero value":      {},
	} {
		got, err := SetupSecurityMounts(&recordingDevices{}, ws, "/workspace", nil, false, nil, scan, false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
}

// gitCmd runs git in dir with an isolated config, allowing file:// submodules.
func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "protocol.file.allow=always", "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// A submodule checkout below nestedGitSearchDepth still gets its .git file
// protected: it is found from the module's core.worktree.
func TestSetupSecurityMounts_DeepSubmoduleGitFile(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	tmp := t.TempDir()
	lib, ws := filepath.Join(tmp, "lib"), filepath.Join(tmp, "ws")
	for _, d := range []string{lib, ws} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		gitCmd(t, d, "init", "-q")
		gitCmd(t, d, "commit", "-q", "--allow-empty", "-m", "init")
	}
	deep := filepath.Join("third_party", "github.com", "org", "lib")
	gitCmd(t, ws, "submodule", "add", "-q", lib, deep)

	got, err := SetupSecurityMounts(&recordingDevices{}, ws, "/workspace", nil, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(deep, ".git"); !slices.Contains(got, want) {
		t.Errorf("expected %q in %v", want, got)
	}
}

func TestSubmoduleGitFile_RejectsUnsafeWorktrees(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws, ".git")
	mkGitDir(t, ws, ".git/modules/lib")
	cfg := filepath.Join(ws, ".git/modules/lib/config")
	write := func(worktree string) {
		t.Helper()
		if err := os.WriteFile(cfg, []byte("[core]\n\tbare = false\n\tworktree = "+worktree+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mkGitFile := func(dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mkGitFile(filepath.Join(ws, "a/b/c/d/lib"))
	write("../../../a/b/c/d/lib")
	if got, ok := submoduleGitFile(ws, ".git/modules/lib"); !ok || got != filepath.Join("a/b/c/d/lib", ".git") {
		t.Errorf("relative core.worktree: got %q, %v", got, ok)
	}

	outside := t.TempDir()
	mkGitFile(outside)
	write(outside)
	if got, ok := submoduleGitFile(ws, ".git/modules/lib"); ok {
		t.Errorf("worktree outside the workspace must be ignored, got %q", got)
	}

	if err := os.Symlink(outside, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(ws, "link"))
	if got, ok := submoduleGitFile(ws, ".git/modules/lib"); ok {
		t.Errorf("worktree through a symlink must be ignored, got %q", got)
	}

	write(filepath.Join(ws, "a/b/c/d"))
	if got, ok := submoduleGitFile(ws, ".git/modules/lib"); ok {
		t.Errorf("worktree without a .git file must be ignored, got %q", got)
	}
}

// [git] writable_hooks leaves the nested hooks dirs writable.
func TestSetupSecurityMounts_WritableHooksSkipsNestedHooks(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	mkGitDir(t, tmp, ".git/modules/lib")
	mkGitDir(t, tmp, "sub/.git")

	got, err := SetupSecurityMounts(&recordingDevices{}, tmp, "/workspace", nil, false, nil, NestedGitScan{}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if filepath.Base(p) == "hooks" {
			t.Errorf("hooks must stay writable, got %q in %v", p, got)
		}
	}
	if !slices.Contains(got, filepath.Join(".git/modules/lib", "config")) || !slices.Contains(got, filepath.Join("sub/.git", "config")) {
		t.Errorf("non-hooks entries must stay protected, got %v", got)
	}
}

// An early scan's result is what gets mounted: a git dir only the given scan
// reports (below the walk depth) is protected.
func TestSetupSecurityMounts_UsesEarlyScan(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws, "a/b/c/d/.git")
	scan := NestedGitScan{workspacePath: ws, result: func() nestedGitFound {
		return nestedGitFound{gitDirs: []string{"a/b/c/d/.git"}}
	}}
	got, err := SetupSecurityMounts(&recordingDevices{}, ws, "/workspace", nil, false, nil, scan, false)
	if err != nil {
		t.Fatal(err)
	}
	assertContainsAll(t, got, gitDirEntries("a/b/c/d/.git"))
}

func TestStartSetupNestedGitScan(t *testing.T) {
	ws := t.TempDir()
	if scan := startSetupNestedGitScan(SetupOptions{WorkspacePath: ws}); scan.result == nil || scan.workspacePath != ws {
		t.Error("Setup must start the nested git scan of its workspace")
	}
	opts := SetupOptions{WorkspacePath: ws}
	opts.Security.Config = &config.SecurityConfig{DisableProtection: true}
	if scan := startSetupNestedGitScan(opts); scan.result != nil {
		t.Error("no scan when protection is disabled")
	}
}

// sessionMountRecorder is a ContainerManager that records disk mounts.
type sessionMountRecorder struct {
	container.ContainerManager
	paths []string
}

func (m *sessionMountRecorder) MountDisk(_, _, path string, _, _ bool) error {
	m.paths = append(m.paths, path)
	return nil
}

func (m *sessionMountRecorder) MountDisks(mounts []container.DiskMount) error {
	for _, d := range mounts {
		m.paths = append(m.paths, d.Path)
	}
	return nil
}

// coi shell passes its writable-hooks signal to the nested git expansion.
func TestApplySessionSecurity_WritableHooksLeavesNestedHooks(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws, ".git")
	mkGitDir(t, ws, ".git/modules/lib")
	nestedHooks := filepath.Join("/workspace", ".git/modules/lib/hooks")
	nestedConfig := filepath.Join("/workspace", ".git/modules/lib/config")

	for _, writable := range []bool{true, false} {
		opts := SetupOptions{WorkspacePath: ws, Logger: func(string) {}}
		opts.Security.ProtectedPaths = []string{".git/config"}
		mgr := &sessionMountRecorder{}
		if _, _, err := applySessionSecurity(mgr, opts, "/workspace", false, nil, writable, "c1", NestedGitScan{}); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(mgr.paths, nestedHooks) == writable {
			t.Errorf("writable=%v: nested hooks mounted=%v, mounts %v", writable, !writable, mgr.paths)
		}
		if !slices.Contains(mgr.paths, nestedConfig) {
			t.Errorf("writable=%v: nested config must stay protected, mounts %v", writable, mgr.paths)
		}
	}
}
