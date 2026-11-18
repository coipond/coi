package session

import (
	"os"
	"path/filepath"
	"testing"
)

// makeWorktree synthesizes a bare-repo + linked-worktree layout under root and
// returns (workspace checkout dir, common dir, worktree gitdir). It mirrors what
// `git worktree add` produces without needing the git binary.
func makeWorktree(t *testing.T, root string) (workspace, common, gitDir string) {
	t.Helper()
	common = filepath.Join(root, "bare")
	gitDir = filepath.Join(common, "worktrees", "wt")
	workspace = filepath.Join(root, "checkout")

	for _, d := range []string{
		filepath.Join(common, "objects"),
		filepath.Join(common, "refs"),
		filepath.Join(common, "hooks"),
		filepath.Join(common, "info"),
		gitDir,
		workspace,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	write := func(p, content string) {
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	// Common dir markers.
	write(filepath.Join(common, "HEAD"), "ref: refs/heads/main\n")
	write(filepath.Join(common, "config"), "[core]\n\trepositoryformatversion = 0\n")
	// Worktree admin files.
	write(filepath.Join(gitDir, "HEAD"), "ref: refs/heads/wt\n")
	write(filepath.Join(gitDir, "commondir"), "../..\n") // relative to gitDir → common
	write(filepath.Join(gitDir, "gitdir"), filepath.Join(workspace, ".git")+"\n")
	// Workspace pointer file.
	write(filepath.Join(workspace, ".git"), "gitdir: "+gitDir+"\n")
	return workspace, common, gitDir
}

func resolvedEqual(t *testing.T, got, want string) {
	t.Helper()
	g, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("evalsymlinks got %q: %v", got, err)
	}
	w, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatalf("evalsymlinks want %q: %v", want, err)
	}
	if g != w {
		t.Errorf("path = %q, want %q", g, w)
	}
}

func TestResolveGitWorktree_Valid(t *testing.T) {
	ws, common, gitDir := makeWorktree(t, t.TempDir())
	layout, err := ResolveGitWorktree(ws)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if layout == nil {
		t.Fatal("expected a layout for a valid worktree")
	}
	resolvedEqual(t, layout.GitDir, gitDir)
	resolvedEqual(t, layout.CommonDir, common)
}

func TestResolveGitWorktree_RelativeCommondir(t *testing.T) {
	// makeWorktree already uses a relative "../.." commondir; assert it resolved
	// to the common dir (relative-to-gitdir, not relative-to-workspace).
	ws, common, _ := makeWorktree(t, t.TempDir())
	layout, err := ResolveGitWorktree(ws)
	if err != nil || layout == nil {
		t.Fatalf("resolve failed: %v", err)
	}
	resolvedEqual(t, layout.CommonDir, common)
}

func TestResolveGitWorktree_PlainDirIsNoop(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	layout, err := ResolveGitWorktree(ws)
	if err != nil || layout != nil {
		t.Fatalf("plain .git dir should be a no-op, got layout=%v err=%v", layout, err)
	}
}

func TestResolveGitWorktree_AbsentGitIsNoop(t *testing.T) {
	layout, err := ResolveGitWorktree(t.TempDir())
	if err != nil || layout != nil {
		t.Fatalf("absent .git should be a no-op, got layout=%v err=%v", layout, err)
	}
}

func TestResolveGitWorktree_SymlinkGitRefused(t *testing.T) {
	ws := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(ws, ".git")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := ResolveGitWorktree(ws); err == nil {
		t.Fatal("a symlinked .git must be refused")
	}
}

func TestResolveGitWorktree_MalformedPointer(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, ".git"), []byte("not a pointer\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGitWorktree(ws); err == nil {
		t.Fatal("a malformed .git pointer must error")
	}
}

func TestResolveGitWorktree_MissingBackPointerRefused(t *testing.T) {
	ws, _, gitDir := makeWorktree(t, t.TempDir())
	if err := os.Remove(filepath.Join(gitDir, "gitdir")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGitWorktree(ws); err == nil {
		t.Fatal("a worktree with no back pointer must be refused")
	}
}

func TestResolveGitWorktree_MismatchedBackPointerRefused(t *testing.T) {
	ws, _, gitDir := makeWorktree(t, t.TempDir())
	// Point the back pointer at a different workspace's .git.
	other := filepath.Join(t.TempDir(), ".git")
	if err := os.WriteFile(other, []byte("gitdir: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "gitdir"), []byte(other+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGitWorktree(ws); err == nil {
		t.Fatal("a mismatched back pointer must be refused (anti ~/.ssh-redirect)")
	}
}

func TestResolveGitWorktree_MissingObjectsRefused(t *testing.T) {
	ws, common, _ := makeWorktree(t, t.TempDir())
	if err := os.RemoveAll(filepath.Join(common, "objects")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGitWorktree(ws); err == nil {
		t.Fatal("a common dir with no objects/ store must be refused")
	}
}

func TestResolveGitWorktree_MissingHeadRefused(t *testing.T) {
	ws, common, _ := makeWorktree(t, t.TempDir())
	if err := os.Remove(filepath.Join(common, "HEAD")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGitWorktree(ws); err == nil {
		t.Fatal("a common dir with no HEAD must be refused")
	}
}

func TestStripGitProtectedPaths(t *testing.T) {
	in := []string{".git/hooks", ".git/config", ".git", ".husky", ".vscode", ".claude/settings.json"}
	got := StripGitProtectedPaths(in)
	want := []string{".husky", ".vscode", ".claude/settings.json"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestWorkspaceUnderSystemDir(t *testing.T) {
	cases := map[string]bool{
		"/usr/local/x":  true,
		"/etc":          true,
		"/lib64/x":      true,
		"/home/u/proj":  false,
		"/etcfoo":       false, // prefix but not a path component
		"/tmp/pytest/x": false,
	}
	for path, want := range cases {
		if got := WorkspaceUnderSystemDir(path); got != want {
			t.Errorf("WorkspaceUnderSystemDir(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestResolveGitWorktree_InsideWorkspaceIsNoop(t *testing.T) {
	// A worktree whose gitdir resolves inside the workspace needs no external
	// mount; the workspace mount already covers it.
	root := t.TempDir()
	ws := filepath.Join(root, "checkout")
	common := filepath.Join(ws, "innergit")
	gitDir := filepath.Join(common, "worktrees", "wt")
	for _, d := range []string{filepath.Join(common, "objects"), gitDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(common, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	os.WriteFile(filepath.Join(gitDir, "commondir"), []byte("../..\n"), 0o644)
	os.WriteFile(filepath.Join(gitDir, "gitdir"), []byte(filepath.Join(ws, ".git")+"\n"), 0o644)
	os.WriteFile(filepath.Join(ws, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644)

	layout, err := ResolveGitWorktree(ws)
	if err != nil || layout != nil {
		t.Fatalf("in-workspace gitdir should be a no-op, got layout=%v err=%v", layout, err)
	}
}

// resolveCommonDir reads commondir as git does: only CR and LF are trimmed,
// and symlinks are resolved before "..".
func TestResolveCommonDir_ReadsLikeGit(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(root, "git")
	for _, d := range []string{gitDir, filepath.Join(root, "x"), filepath.Join(root, "x "), filepath.Join(root, "d", "real.git", "x")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("..", "d", "real.git", "x"), filepath.Join(gitDir, "lnk")); err != nil {
		t.Fatal(err)
	}
	for content, want := range map[string]string{
		"../x \r\n": filepath.Join(root, "x "),
		"lnk/..\n":  filepath.Join(root, "d", "real.git"),
	} {
		if err := os.WriteFile(filepath.Join(gitDir, "commondir"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := resolveCommonDir(gitDir); err != nil || got != want {
			t.Errorf("commondir %q: resolveCommonDir = %q, %v; want %q", content, got, err, want)
		}
	}
}
