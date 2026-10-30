package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// Against a real tmux: a pane left in copy mode (a mouse wheel scroll) still
// runs the command sent into it.
func TestTmuxSendKeysCmd_LeavesCopyMode(t *testing.T) {
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed")
	}
	dir := t.TempDir()
	tmux := func(args ...string) error {
		c := exec.Command("tmux", args...)
		c.Env = append(os.Environ(), "TMUX_TMPDIR="+dir, "TMUX=")
		return c.Run()
	}
	t.Cleanup(func() { _ = tmux("kill-server") })

	if err := tmux("-f", "/dev/null", "new-session", "-d", "-s", session.TmuxSessionName("c1"), "sh"); err != nil {
		t.Fatalf("new-session: %v", err)
	}
	if err := tmux("copy-mode", "-t", session.TmuxPaneTarget("c1")); err != nil {
		t.Fatalf("copy-mode: %v", err)
	}

	marker := filepath.Join(dir, "ran")
	send := exec.Command("bash", "-c", tmuxSendKeysCmd("c1", "touch "+marker))
	send.Env = append(os.Environ(), "TMUX_TMPDIR="+dir, "TMUX=")
	if out, err := send.CombinedOutput(); err != nil {
		t.Fatalf("send: %v: %s", err, out)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("command sent to a pane in copy mode did not run")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
