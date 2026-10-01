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
	// Seed a first commit: the guard deliberately lets the root commit of a
	// new repo through (TestBranchGuard_FirstCommitAllowed_Exec).
	if out, err := git(t, repo, nil, "commit", "--allow-empty", "-m", "seed"); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
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

// The first commit of a brand-new repository has nothing to protect and no
// branch to fork a feature from, so `git init && git commit` must work (it is
// also what project test suites do in throwaway repos).
func TestBranchGuard_FirstCommitAllowed_Exec(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	if out, err := git(t, repo, nil, "init", "-b", "main"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	installGuards(t, repo, filepath.Join(t.TempDir(), "hooks"), []string{"main"})
	if out, err := git(t, repo, nil, "commit", "--allow-empty", "-m", "root"); err != nil {
		t.Fatalf("first commit should be allowed: %v\n%s", err, out)
	}
	// ...but the second one is guarded as usual.
	if out, err := git(t, repo, nil, "commit", "--allow-empty", "-m", "second"); err == nil {
		t.Fatalf("second commit on main should be rejected:\n%s", out)
	}
}

// refTxFixture is a clone of a bare remote whose main has one pushed commit,
// plus an unpushed feature branch with one commit, with the guard installed.
func refTxFixture(t *testing.T) (repo string) {
	t.Helper()
	requireGit(t)
	remote := t.TempDir()
	if out, err := git(t, remote, nil, "init", "-q", "--bare", "-b", "main"); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}
	seed := t.TempDir()
	if err := os.WriteFile(filepath.Join(seed, "base.txt"), []byte("base"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"add", "base.txt"}, // non-empty, so `git revert HEAD` has something to undo
		{"commit", "-q", "-m", "base"},
		{"remote", "add", "origin", remote},
		{"push", "-q", "origin", "main"},
	} {
		if out, err := git(t, seed, nil, args...); err != nil {
			t.Fatalf("seed %v: %v\n%s", args, err, out)
		}
	}
	repo = filepath.Join(t.TempDir(), "clone")
	if out, err := git(t, t.TempDir(), nil, "clone", "-q", remote, repo); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if out, err := git(t, repo, nil, "switch", "-q", "-c", "feature"); err != nil {
		t.Fatalf("switch: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(repo, "feat.txt"), []byte("feat"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "feat.txt"}, {"commit", "-q", "-m", "feat"}} {
		if out, err := git(t, repo, nil, args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	installGuards(t, repo, filepath.Join(t.TempDir(), "hooks"), []string{"main"})
	if out, err := git(t, repo, nil, "switch", "-q", "main"); err != nil {
		t.Fatalf("switch main: %v\n%s", err, out)
	}
	return repo
}

func revParse(t *testing.T, repo, rev string) string {
	t.Helper()
	out, err := git(t, repo, nil, "rev-parse", rev)
	if err != nil {
		t.Fatalf("rev-parse %s: %v\n%s", rev, err, out)
	}
	return strings.TrimSpace(out)
}

// Commands that move a protected branch WITHOUT running pre-commit or
// pre-merge-commit must still be refused (via reference-transaction), and
// main must be left where it was.
func TestBranchGuard_RefTransaction_BlocksNonCommitPaths_Exec(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, repo string) (string, error)
	}{
		{"cherry-pick", func(t *testing.T, repo string) (string, error) {
			return git(t, repo, nil, "cherry-pick", "feature")
		}},
		{"revert", func(t *testing.T, repo string) (string, error) {
			return git(t, repo, nil, "revert", "--no-edit", "HEAD")
		}},
		{"fast-forward merge", func(t *testing.T, repo string) (string, error) {
			return git(t, repo, nil, "merge", "--ff-only", "feature")
		}},
		{"reset to local commit", func(t *testing.T, repo string) (string, error) {
			return git(t, repo, nil, "reset", "--hard", "feature")
		}},
		{"rebase onto local branch", func(t *testing.T, repo string) (string, error) {
			return git(t, repo, nil, "rebase", "feature")
		}},
		{"update-ref", func(t *testing.T, repo string) (string, error) {
			return git(t, repo, nil, "update-ref", "refs/heads/main", "feature")
		}},
		{"branch -f from elsewhere", func(t *testing.T, repo string) (string, error) {
			if out, err := git(t, repo, nil, "switch", "-q", "feature"); err != nil {
				return out, nil // setup failure surfaces as "not blocked"
			}
			return git(t, repo, nil, "branch", "-f", "main", "feature")
		}},
		{"am", func(t *testing.T, repo string) (string, error) {
			patch, err := git(t, repo, nil, "format-patch", "-1", "--stdout", "feature")
			if err != nil {
				return patch, nil
			}
			f := filepath.Join(t.TempDir(), "p.patch")
			if err := os.WriteFile(f, []byte(patch), 0o644); err != nil {
				t.Fatal(err)
			}
			return git(t, repo, nil, "am", f)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := refTxFixture(t)
			before := revParse(t, repo, "main")
			out, err := tc.run(t, repo)
			if err == nil {
				t.Errorf("%s onto main should be refused, got:\n%s", tc.name, out)
			}
			if !strings.Contains(out, "refusing to move protected branch 'main'") {
				t.Errorf("rejection should come from the branch guard, got:\n%s", out)
			}
			if after := revParse(t, repo, "main"); after != before {
				t.Errorf("main moved from %s to %s", before, after)
			}
		})
	}
}

// Syncing a protected branch with its remote, and everyday work on other
// branches, must keep working under the reference-transaction guard.
func TestBranchGuard_RefTransaction_AllowsSyncAndFeatureWork_Exec(t *testing.T) {
	repo := refTxFixture(t)

	// Someone else advances origin/main; a fast-forward pull must succeed.
	other := filepath.Join(t.TempDir(), "other")
	remote, _ := git(t, repo, nil, "remote", "get-url", "origin")
	if out, err := git(t, t.TempDir(), nil, "clone", "-q", strings.TrimSpace(remote), other); err != nil {
		t.Fatalf("clone other: %v\n%s", err, out)
	}
	for _, args := range [][]string{{"commit", "-q", "--allow-empty", "-m", "upstream"}, {"push", "-q", "origin", "main"}} {
		if out, err := git(t, other, nil, args...); err != nil {
			t.Fatalf("other %v: %v\n%s", args, err, out)
		}
	}
	if out, err := git(t, repo, nil, "pull", "-q", "--ff-only"); err != nil {
		t.Fatalf("ff pull of main should be allowed: %v\n%s", err, out)
	}
	if revParse(t, repo, "main") != revParse(t, repo, "origin/main") {
		t.Error("main did not advance to origin/main")
	}

	// Resetting back to an upstream commit is fine too.
	if out, err := git(t, repo, nil, "reset", "-q", "--hard", "origin/main~1"); err != nil {
		t.Fatalf("reset to an upstream commit should be allowed: %v\n%s", err, out)
	}

	// Feature-branch work, creating and deleting branches.
	for _, args := range [][]string{
		{"switch", "-q", "feature"},
		{"commit", "-q", "--allow-empty", "-m", "more"},
		{"cherry-pick", "--allow-empty", "--keep-redundant-commits", "main"},
		{"branch", "scratch"},
		{"branch", "-D", "scratch"},
		{"fetch", "-q"},
	} {
		if out, err := git(t, repo, nil, args...); err != nil {
			t.Errorf("%v should be allowed: %v\n%s", args, err, out)
		}
	}
}

// The guard hands off to the repo's own hooks from the COMMON git dir, so a
// linked worktree (whose --git-dir has no hooks/) still runs them.
func TestBranchGuard_DelegatesFromLinkedWorktree_Exec(t *testing.T) {
	repo := refTxFixture(t)
	marker := filepath.Join(t.TempDir(), "ran")
	repoHook := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(repoHook, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	wt := filepath.Join(t.TempDir(), "wt")
	if out, err := git(t, repo, nil, "worktree", "add", "-q", "-b", "wt-branch", wt); err != nil {
		t.Fatalf("worktree add: %v\n%s", err, out)
	}
	if out, err := git(t, wt, nil, "commit", "-q", "--allow-empty", "-m", "in worktree"); err != nil {
		t.Fatalf("commit in worktree: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("repo's own pre-commit hook did not run from a linked worktree")
	}
}

// Recreating a protected branch over a local-only commit is moving it too:
// delete+recreate, checkout -B and switch -C must all be refused, leaving main
// unable to point at the local commit. (branch -M/-C over main aren't covered:
// git 2.43 doesn't run reference-transaction for rename/copy.)
func TestBranchGuard_RefTransaction_BlocksRecreate_Exec(t *testing.T) {
	cases := []struct {
		name  string
		steps [][]string // all but the last must succeed; the last must be refused
	}{
		{"delete then recreate", [][]string{{"switch", "-q", "feature"}, {"branch", "-D", "main"}, {"branch", "main", "feature"}}},
		{"checkout -B main", [][]string{{"switch", "-q", "feature"}, {"checkout", "-B", "main", "feature"}}},
		{"switch -C main", [][]string{{"switch", "-q", "feature"}, {"switch", "-C", "main", "feature"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := refTxFixture(t)
			local := revParse(t, repo, "feature")
			last := len(tc.steps) - 1
			for _, args := range tc.steps[:last] {
				if out, err := git(t, repo, nil, args...); err != nil {
					t.Fatalf("setup %v: %v\n%s", args, err, out)
				}
			}
			out, err := git(t, repo, nil, tc.steps[last]...)
			if err == nil || !strings.Contains(out, "refusing to move protected branch 'main'") {
				t.Errorf("%v should be refused by the guard (err=%v):\n%s", tc.steps[last], err, out)
			}
			if got, _ := git(t, repo, nil, "rev-parse", "-q", "--verify", "refs/heads/main"); strings.TrimSpace(got) == local {
				t.Errorf("main now points at the local-only commit %s", local)
			}
		})
	}
}

// `git fetch origin main:main` moves main BEFORE origin/main (two separate
// transactions), so the guard can't tell it from a local fast-forward and
// refuses it — with a message naming the alternative, which must work:
// fetch, then point main at the remote-tracking ref. Recreating main from the
// remote (git switch after deleting it) is fine too.
func TestBranchGuard_RefTransaction_SyncFromRemote_Exec(t *testing.T) {
	repo := refTxFixture(t)
	remote, _ := git(t, repo, nil, "remote", "get-url", "origin")
	other := filepath.Join(t.TempDir(), "other")
	if out, err := git(t, t.TempDir(), nil, "clone", "-q", strings.TrimSpace(remote), other); err != nil {
		t.Fatalf("clone other: %v\n%s", err, out)
	}
	for _, args := range [][]string{{"commit", "-q", "--allow-empty", "-m", "upstream"}, {"push", "-q", "origin", "main"}} {
		if out, err := git(t, other, nil, args...); err != nil {
			t.Fatalf("other %v: %v\n%s", args, err, out)
		}
	}
	if out, err := git(t, repo, nil, "switch", "-q", "feature"); err != nil {
		t.Fatalf("switch: %v\n%s", err, out)
	}
	out, err := git(t, repo, nil, "fetch", "-q", "origin", "main:main")
	if err == nil {
		t.Fatalf("fetch origin main:main is expected to be refused (git moves main first):\n%s", out)
	}
	if !strings.Contains(out, "git branch -f main <remote>/main") {
		t.Errorf("refusal should name the working alternative:\n%s", out)
	}
	for _, args := range [][]string{
		{"fetch", "-q", "origin"},
		{"branch", "-f", "main", "origin/main"}, // the suggested alternative
		{"branch", "-D", "main"},
		{"switch", "-q", "main"}, // DWIM: recreate main from origin/main
	} {
		if out, err := git(t, repo, nil, args...); err != nil {
			t.Errorf("%v should be allowed: %v\n%s", args, err, out)
		}
	}
	if revParse(t, repo, "main") != revParse(t, repo, "origin/main") {
		t.Error("main should match origin/main")
	}
}

// With the guard as the GLOBAL hooks path (as coi installs it), cloning,
// pushing into a local bare repository, and building a fresh repo from
// scratch must all keep working.
func TestBranchGuard_RefTransaction_GlobalHooksPath_Exec(t *testing.T) {
	requireGit(t)
	hooks := filepath.Join(t.TempDir(), "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range branchGuardHooks {
		if err := os.WriteFile(filepath.Join(hooks, name), []byte(renderBranchGuardScript(name, []string{"main"})), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gcfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(gcfg, []byte("[core]\n\thooksPath = "+hooks+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"GIT_CONFIG_GLOBAL=" + gcfg}

	// Fresh repo + bare "server" fixture, as a project test suite would build.
	bare := filepath.Join(t.TempDir(), "srv.git")
	work := filepath.Join(t.TempDir(), "work")
	for _, step := range []struct {
		dir  string
		args []string
	}{
		{t.TempDir(), []string{"init", "-q", "--bare", "-b", "main", bare}},
		{t.TempDir(), []string{"init", "-q", "-b", "main", work}},
		{work, []string{"commit", "-q", "--allow-empty", "-m", "root"}}, // first commit: allowed
		{work, []string{"remote", "add", "origin", bare}},
	} {
		if out, err := git(t, step.dir, env, step.args...); err != nil {
			t.Fatalf("%v: %v\n%s", step.args, err, out)
		}
	}
	// The client-side pre-push refuses pushing to main...
	if out, err := git(t, work, env, "push", "-q", "origin", "main"); err == nil {
		t.Errorf("push to main should still be refused by pre-push:\n%s", out)
	}
	// ...but the bare repo's own reference-transaction must not reject the
	// receive (that broke local bare-repo fixtures): push with the client
	// guard bypassed and the server side has to accept it.
	// Two pushes: the first only CREATES main in the bare repo; the second
	// UPDATES it, which is what the receiving side used to refuse.
	for _, args := range [][]string{
		{"push", "-q", "--no-verify", "origin", "main"},
		{"commit", "-q", "--allow-empty", "-m", "second"},
		{"push", "-q", "--no-verify", "origin", "main"},
	} {
		if args[0] == "commit" {
			// Commit with hooks off: the local guard isn't what's under test
			// here (it would rightly refuse); the receiving side is.
			if out, err := git(t, work, append(env, "GIT_CONFIG_PARAMETERS='core.hooksPath'='/dev/null'"), args...); err != nil {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
			continue
		}
		if out, err := git(t, work, env, args...); err != nil {
			t.Errorf("bare receiving repo must not reject %v: %v\n%s", args, err, out)
		}
	}
	// Cloning creates main from the remote.
	clone := filepath.Join(t.TempDir(), "clone")
	if out, err := git(t, t.TempDir(), env, "clone", "-q", bare, clone); err != nil {
		t.Errorf("clone should work under the guard: %v\n%s", err, out)
	}
}

// A repository with no remote-tracking refs may create a protected branch from
// existing work: `git init -b dev`, a couple of commits, then
// `git checkout -b main` is ordinary and must not be refused.
func TestBranchGuard_RefTransaction_CreateMainInLocalOnlyRepo_Exec(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	if out, err := git(t, repo, nil, "init", "-q", "-b", "dev"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	for _, msg := range []string{"one", "two"} {
		if out, err := git(t, repo, nil, "commit", "-q", "--allow-empty", "-m", msg); err != nil {
			t.Fatalf("commit %s: %v\n%s", msg, err, out)
		}
	}
	installGuards(t, repo, filepath.Join(t.TempDir(), "hooks"), []string{"main"})
	if out, err := git(t, repo, nil, "checkout", "-q", "-b", "main"); err != nil {
		t.Errorf("creating main in a repo without remotes should be allowed: %v\n%s", err, out)
	}
}

// The remote-known check fails CLOSED: a broken remote-tracking ref makes
// rev-list error out, and that must not read as "a remote has the commit".
func TestBranchGuard_RefTransaction_BrokenRemoteRefFailsClosed_Exec(t *testing.T) {
	repo := refTxFixture(t)
	gitDir := filepath.Join(repo, ".git")
	broken := filepath.Join(gitDir, "refs", "remotes", "x", "broken")
	if err := os.MkdirAll(filepath.Dir(broken), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broken, []byte(strings.Repeat("1", 40)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := git(t, repo, nil, "switch", "-q", "feature"); err != nil {
		t.Fatalf("switch: %v\n%s", err, out)
	}
	out, err := git(t, repo, nil, "branch", "-f", "main", "feature")
	if err == nil || !strings.Contains(out, "refusing to move protected branch 'main'") {
		t.Errorf("a broken remote ref must not open the guard (err=%v):\n%s", err, out)
	}
}
