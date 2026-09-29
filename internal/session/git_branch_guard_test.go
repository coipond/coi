package session

import (
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
	if !strings.Contains(s, "git symbolic-ref --short -q HEAD") {
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
