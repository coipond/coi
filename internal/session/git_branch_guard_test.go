package session

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The pre-commit guard must: check HEAD's branch, reject each protected branch
// with a message, and delegate to the repo's own pre-commit at the end.
func TestRenderBranchGuardScript_PreCommit(t *testing.T) {
	s := renderBranchGuardScript("pre-commit", []string{"main", "master"})

	if !strings.HasPrefix(s, "#!/bin/sh") {
		t.Fatal("missing shebang")
	}
	if !strings.Contains(s, "git symbolic-ref -q HEAD") {
		t.Error("pre-commit must resolve the current branch")
	}
	for _, b := range []string{"main", "master"} {
		if !strings.Contains(s, "[ \"$branch\" = '"+b+"' ]") {
			t.Errorf("missing string-equality check for %q:\n%s", b, s)
		}
	}
	if !strings.Contains(s, "refusing to commit on protected branch") {
		t.Error("missing rejection message")
	}
	if !strings.Contains(s, "git switch -c") {
		t.Error("should hint how to make a feature branch")
	}
	// Delegation to the repository's own hook, run only on the allowed path.
	if !strings.Contains(s, "/hooks/pre-commit") || !strings.Contains(s, `exec "$hook"`) {
		t.Error("missing delegation to the repo pre-commit hook")
	}
}

// pre-merge-commit shares the commit-style guard (a non-ff `git merge` commits
// WITHOUT firing pre-commit), and must delegate to the repo's own
// pre-merge-commit — not pre-commit.
func TestRenderBranchGuardScript_PreMergeCommit(t *testing.T) {
	s := renderBranchGuardScript("pre-merge-commit", []string{"main"})

	if !strings.Contains(s, "git symbolic-ref -q HEAD") {
		t.Error("pre-merge-commit must resolve the current branch (same as pre-commit)")
	}
	if !strings.Contains(s, "[ \"$branch\" = 'main' ]") {
		t.Errorf("missing string-equality check for main:\n%s", s)
	}
	if !strings.Contains(s, "/hooks/pre-merge-commit") {
		t.Errorf("must delegate to the repo's own pre-merge-commit hook, not a fixed one:\n%s", s)
	}
	if strings.Contains(s, "/hooks/pre-commit") {
		t.Errorf("pre-merge-commit guard must not delegate to pre-commit:\n%s", s)
	}
}

// The pre-push guard must buffer stdin, parse ref lines, reject pushes whose
// destination is a protected branch, and replay stdin to the delegated hook.
func TestRenderBranchGuardScript_PrePush(t *testing.T) {
	s := renderBranchGuardScript("pre-push", []string{"main"})

	if !strings.Contains(s, `input="$(cat)"`) {
		t.Error("pre-push must buffer stdin (git feeds refs there)")
	}
	if !strings.Contains(s, "refs/heads/*") || !strings.Contains(s, "${rref#refs/heads/}") {
		t.Error("pre-push must extract the branch from the remote ref")
	}
	if !strings.Contains(s, "[ \"$rb\" = 'main' ]") {
		t.Errorf("missing string-equality check for main:\n%s", s)
	}
	if !strings.Contains(s, "refusing to push to protected branch") {
		t.Error("missing rejection message")
	}
	// A here-doc feeds the loop in the CURRENT shell (a pipe subshell could not
	// exit the hook); delegation replays the buffered refs on the hook's stdin.
	if !strings.Contains(s, "<<COI_PROTECTED_REFS") {
		t.Error("pre-push must drive the read loop from a here-doc, not a pipe")
	}
	if strings.Contains(s, `input="$(cat)"`) && strings.Contains(s, `| while read`) {
		t.Error("pre-push must NOT pipe into `while` — exit 1 in the subshell would not fail the hook")
	}
	if !strings.Contains(s, "/hooks/pre-push") {
		t.Error("missing delegation to the repo pre-push hook")
	}
}

// Branch names are single-quoted (shellEscape), so a name carrying shell/glob
// metacharacters can neither be mis-matched nor injected.
func TestRenderBranchGuardScript_Injection(t *testing.T) {
	evil := "main'; rm -rf / #"
	s := renderBranchGuardScript("pre-commit", []string{evil})
	if strings.Contains(s, "rm -rf / #\n") && !strings.Contains(s, `'main'\''; rm -rf / #'`) {
		t.Errorf("branch name not shell-escaped, injection possible:\n%s", s)
	}
	// The escaped form must appear as a quoted literal in the comparison.
	if !strings.Contains(s, shellEscape(evil)) {
		t.Errorf("expected shell-escaped literal %q in script:\n%s", shellEscape(evil), s)
	}
}

// A tag sharing the protected branch's name makes `git symbolic-ref --short`
// print "heads/main", which once slipped past the string-equality check. Run
// the rendered hook in a real repo to prove the commit is still refused.
func TestBranchGuard_TagNamedLikeBranchStillBlocks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	hooks := filepath.Join(dir, "hooks")
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	script := renderBranchGuardScript("pre-commit", []string{"main"})
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := exec.Command("git", "init", "-q", "-b", "main", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	// Seed a commit (hooks not yet active) so the tag has something to point at.
	if out, err := git("commit", "-q", "--allow-empty", "-m", "seed"); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	if out, err := git("tag", "main"); err != nil {
		t.Fatalf("git tag: %v\n%s", err, out)
	}
	if out, err := git("config", "core.hooksPath", hooks); err != nil {
		t.Fatalf("set hooksPath: %v\n%s", err, out)
	}

	out, err := git("commit", "--allow-empty", "-m", "on main")
	if err == nil {
		t.Fatalf("commit on main succeeded despite the guard (tag named main):\n%s", out)
	}
	if !strings.Contains(out, "refusing to commit on protected branch 'main'") {
		t.Errorf("expected guard rejection message, got:\n%s", out)
	}

	// Control: a feature branch is still allowed.
	if out, err := git("switch", "-q", "-c", "feature"); err != nil {
		t.Fatalf("switch: %v\n%s", err, out)
	}
	if out, err := git("commit", "-q", "--allow-empty", "-m", "on feature"); err != nil {
		t.Errorf("commit on feature branch should pass the guard: %v\n%s", err, out)
	}
}
