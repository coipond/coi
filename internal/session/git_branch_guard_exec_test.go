package session

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests EXECUTE the rendered guard scripts against a real git repo, so the
// shell logic itself is verified — the here-doc-driven read loop (not a piped
// subshell), the string-equality branch match, and delegation. Requires git +
// /bin/sh; skipped where unavailable.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
}

func git(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// Deterministic identity + hooks path; inherit PATH for git's own subprocesses.
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
	)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// installGuards writes the rendered pre-commit + pre-push scripts into hooksDir
// and points the repo's core.hooksPath at it.
func installGuards(t *testing.T, repo, hooksDir string, branches []string) {
	t.Helper()
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range branchGuardHooks {
		p := filepath.Join(hooksDir, name)
		if err := os.WriteFile(p, []byte(renderBranchGuardScript(name, branches)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := git(t, repo, nil, "config", "core.hooksPath", hooksDir); err != nil {
		t.Fatalf("set hooksPath: %v\n%s", err, out)
	}
}

func TestBranchGuard_PreCommit_Exec(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	if out, err := git(t, repo, nil, "init", "-b", "main"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	installGuards(t, repo, filepath.Join(t.TempDir(), "hooks"), []string{"main", "master"})

	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := git(t, repo, nil, "add", "f.txt"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}

	// NEGATIVE: committing on the protected branch is rejected.
	out, err := git(t, repo, nil, "commit", "-m", "on main")
	if err == nil {
		t.Fatalf("commit on main should have been rejected, got:\n%s", out)
	}
	if !strings.Contains(out, "refusing to commit on protected branch 'main'") {
		t.Errorf("missing/incorrect rejection message:\n%s", out)
	}

	// POSITIVE: the same commit succeeds on a feature branch.
	if out, err := git(t, repo, nil, "switch", "-c", "feature"); err != nil {
		t.Fatalf("switch: %v\n%s", err, out)
	}
	if out, err := git(t, repo, nil, "commit", "-m", "on feature"); err != nil {
		t.Fatalf("commit on feature should succeed, got:\n%s", out)
	}
}

// A non-fast-forward `git merge` onto a protected branch commits WITHOUT firing
// pre-commit — only pre-merge-commit runs. This test would pass a merge through
// if the guard covered pre-commit alone.
func TestBranchGuard_MergeOntoProtected_Exec(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	if out, err := git(t, repo, nil, "init", "-b", "main"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	hooks := filepath.Join(t.TempDir(), "hooks")

	// Seed an initial commit on main BEFORE installing the guard, then branch off
	// and add a divergent commit so the later merge is a real (non-ff) merge.
	writeCommit := func(branch, file, content, msg string) {
		if out, err := git(t, repo, nil, "checkout", "-q", branch); err != nil {
			// -b when the branch doesn't exist yet
			if out2, err2 := git(t, repo, nil, "checkout", "-q", "-b", branch); err2 != nil {
				t.Fatalf("checkout %s: %v / %v\n%s%s", branch, err, err2, out, out2)
			}
		}
		if err := os.WriteFile(filepath.Join(repo, file), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := git(t, repo, nil, "add", file); err != nil {
			t.Fatalf("add: %v\n%s", err, out)
		}
		if out, err := git(t, repo, nil, "commit", "-m", msg); err != nil {
			t.Fatalf("commit %s: %v\n%s", msg, err, out)
		}
	}
	writeCommit("main", "base.txt", "base", "base")
	writeCommit("feature", "feat.txt", "feat", "feat") // creates feature off main
	// A divergent commit on main so `git merge feature` is non-ff (needs a commit).
	writeCommit("main", "main-only.txt", "mainonly", "main diverge")

	installGuards(t, repo, hooks, []string{"main", "master"})

	// NEGATIVE: merging a feature branch INTO main must be blocked by the guard,
	// via the pre-merge-commit hook (pre-commit never fires for a merge).
	out, err := git(t, repo, nil, "merge", "--no-ff", "feature")
	if err == nil {
		t.Fatalf("merge onto main should be blocked by the guard, got:\n%s", out)
	}
	if !strings.Contains(out, "refusing to commit on protected branch 'main'") {
		t.Errorf("merge rejection should come from the branch guard, got:\n%s", out)
	}
}

func TestBranchGuard_PrePush_Exec(t *testing.T) {
	requireGit(t)

	// Bare "remote".
	remote := t.TempDir()
	if out, err := git(t, remote, nil, "init", "--bare", "-b", "main"); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}

	// Work repo with a commit, guards installed AFTER the initial commit so the
	// commit itself isn't blocked (we only test push here).
	repo := t.TempDir()
	if out, err := git(t, repo, nil, "init", "-b", "main"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := git(t, repo, nil, "add", "f.txt"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if out, err := git(t, repo, nil, "commit", "-m", "init"); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	if out, err := git(t, repo, nil, "remote", "add", "origin", remote); err != nil {
		t.Fatalf("remote add: %v\n%s", err, out)
	}
	installGuards(t, repo, filepath.Join(t.TempDir(), "hooks"), []string{"main", "master"})

	// NEGATIVE: pushing to the protected branch is rejected.
	out, err := git(t, repo, nil, "push", "origin", "main")
	if err == nil {
		t.Fatalf("push to main should have been rejected, got:\n%s", out)
	}
	if !strings.Contains(out, "refusing to push to protected branch 'main'") {
		t.Errorf("missing/incorrect rejection message:\n%s", out)
	}

	// POSITIVE: pushing a feature branch (different remote ref) succeeds.
	if out, err := git(t, repo, nil, "switch", "-c", "feature"); err != nil {
		t.Fatalf("switch: %v\n%s", err, out)
	}
	if out, err := git(t, repo, nil, "push", "origin", "feature"); err != nil {
		t.Fatalf("push feature should succeed, got:\n%s", out)
	}
}
