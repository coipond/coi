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
	tmux, sock := testTmux(t)
	dir := filepath.Dir(sock)

	start := func(name, marker string) string {
		t.Helper()
		ch := tmuxStartChannel(name)
		// The test server has its own socket, so point the pane's tmux at it.
		cmd := strings.Replace(tmuxGatedCommand(ch, "touch "+marker), "tmux wait-for", "tmux -S "+sock+" wait-for", 1)
		if err := tmux("new-session", "-d", "-s", name, "bash -c '"+cmd+"; sleep 30'"); err != nil {
			t.Fatalf("new-session: %v", err)
		}
		return ch
	}

	marker := filepath.Join(dir, "started")
	ch := start("coi-gate-test", marker)
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
	cmd := strings.Replace(tmuxGatedCommand(ch2, "touch "+marker2), "tmux wait-for", "tmux -S "+sock+" wait-for", 1)
	if err := tmux("new-session", "-d", "-s", "coi-gate-test2", "bash -c '"+cmd+"; sleep 30'"); err != nil {
		t.Fatalf("new-session: %v", err)
	}
	waitFor(t, marker2)
}

// A gate nobody releases (coi was interrupted) must not start the tool when
// it times out, and the pane says why.
func TestTmuxStartGate_TimeoutDoesNotStart(t *testing.T) {
	tmux, sock := testTmux(t)
	old := tmuxStartGateTimeout
	tmuxStartGateTimeout = 1
	t.Cleanup(func() { tmuxStartGateTimeout = old })

	marker := filepath.Join(filepath.Dir(sock), "started")
	cmd := strings.Replace(tmuxGatedCommand(tmuxStartChannel("coi-t"), "touch "+marker), "tmux wait-for", "tmux -S "+sock+" wait-for", 1)
	if err := tmux("new-session", "-d", "-s", "coi-t", "bash -c '"+cmd+"; sleep 30'"); err != nil {
		t.Fatalf("new-session: %v", err)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the tool started after its gate timed out")
	}
	out, _ := exec.Command("tmux", "-S", sock, "capture-pane", "-t", "=coi-t:", "-p").Output()
	if !strings.Contains(string(out), "the tool was not started") {
		t.Errorf("pane doesn't say why:\n%s", out)
	}
}

// Each launch gets its own channel, so a late signal for one gate can't open
// another's.
func TestTmuxStartChannel_Unique(t *testing.T) {
	a, b := tmuxStartChannel("coi-x"), tmuxStartChannel("coi-x")
	if a == b || !strings.HasPrefix(a, "coi-x-start-") {
		t.Errorf("channels %q and %q", a, b)
	}
}

func testTmux(t *testing.T) (func(args ...string) error, string) {
	t.Helper()
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed")
	}
	sock := filepath.Join(t.TempDir(), "sock")
	tmux := func(args ...string) error {
		return exec.Command("tmux", append([]string{"-S", sock}, args...)...).Run()
	}
	t.Cleanup(func() { _ = tmux("kill-server") })
	return tmux, sock
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
