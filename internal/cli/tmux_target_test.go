package cli

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/session"
)

// The prep script finds the session by exact name: a bare tmux target also
// matches any session it prefixes, like a user's "coi-<container>-dev".
func TestBuildTmuxPrepScript_ExactSessionName(t *testing.T) {
	script := buildTmuxPrepScript("coi-x-1", "true", nil)
	if !strings.Contains(script, "has-session -t '=coi-x-1'") {
		t.Errorf("prep script does not match exactly:\n%s", script)
	}
}

// Against a real tmux: the session and pane targets coi uses don't match a
// session the tool's name merely prefixes, and do match the tool's own.
func TestTmuxTargets_Exact(t *testing.T) {
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed")
	}
	sock := filepath.Join(t.TempDir(), "sock")
	tmux := func(args ...string) error {
		return exec.Command("tmux", append([]string{"-S", sock}, args...)...).Run()
	}
	t.Cleanup(func() { _ = tmux("kill-server") })

	if err := tmux("new-session", "-d", "-s", session.TmuxSessionName("c1")+"-dev", "sleep 30"); err != nil {
		t.Fatalf("new-session: %v", err)
	}
	if tmux("has-session", "-t", session.TmuxSessionTarget("c1")) == nil {
		t.Error("session target matched a prefixed session")
	}
	if tmux("capture-pane", "-p", "-t", session.TmuxPaneTarget("c1")) == nil {
		t.Error("pane target matched a prefixed session")
	}
	if err := tmux("new-session", "-d", "-s", session.TmuxSessionName("c1"), "sleep 30"); err != nil {
		t.Fatalf("new-session: %v", err)
	}
	if err := tmux("has-session", "-t", session.TmuxSessionTarget("c1")); err != nil {
		t.Errorf("session target missed the session: %v", err)
	}
	if err := tmux("capture-pane", "-p", "-t", session.TmuxPaneTarget("c1")); err != nil {
		t.Errorf("pane target missed the session: %v", err)
	}
}
