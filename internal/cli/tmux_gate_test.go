package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The prep script finds the session by exact name: a bare tmux target also
// matches any session it prefixes, like a user's "coi-<container>-dev".
func TestBuildTmuxPrepScript_ExactSessionName(t *testing.T) {
	script := buildTmuxPrepScript("coi-x-1", "true", nil)
	if !strings.Contains(script, "has-session -t '=coi-x-1'") {
		t.Errorf("prep script does not match exactly:\n%s", script)
	}
}

// A new session's pane holds the tool back until the start signal, and a
// signal sent before the pane starts waiting is not lost.
func TestTmuxStartGate(t *testing.T) {
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock")
	marker := filepath.Join(dir, "started")
	tmux := func(args ...string) error {
		return exec.Command("tmux", append([]string{"-S", sock}, args...)...).Run()
	}
	t.Cleanup(func() { _ = tmux("kill-server") })

	ch := tmuxStartChannel("coi-gate-test")
	gated := "timeout 20 tmux -S " + sock + " wait-for " + ch + " 2>/dev/null; touch " + marker
	if err := tmux("new-session", "-d", "-s", "coi-gate-test", "bash -c '"+gated+"; sleep 30'"); err != nil {
		t.Fatalf("new-session: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the tool started before the signal")
	}
	if err := tmux("wait-for", "-S", ch); err != nil {
		t.Fatalf("signal: %v", err)
	}
	waitFor(t, marker)

	// Signal first, pane second: the pane must still start.
	marker2 := filepath.Join(dir, "started2")
	ch2 := tmuxStartChannel("coi-gate-test2")
	if err := tmux("wait-for", "-S", ch2); err != nil {
		t.Fatalf("early signal: %v", err)
	}
	gated2 := "timeout 20 tmux -S " + sock + " wait-for " + ch2 + " 2>/dev/null; touch " + marker2
	if err := tmux("new-session", "-d", "-s", "coi-gate-test2", "bash -c '"+gated2+"; sleep 30'"); err != nil {
		t.Fatalf("new-session: %v", err)
	}
	waitFor(t, marker2)
}

func waitFor(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
}
