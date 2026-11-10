package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/session"
)

const toolMissingHint = "add it to [container.build] agents, run coi build --force"

// runGuarded runs a guarded launch command the way incus exec does (bash -c)
// in dir, which holds a file named "c" so an unescaped [container.build]
// would glob to it.
func runGuarded(t *testing.T, dir, script string) (string, int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "c"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(out), exitErr.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

func TestGuardToolInstalled_Missing(t *testing.T) {
	dir := t.TempDir()
	out, code := runGuarded(t, dir, guardToolInstalled("codex", "coi-no-such-agent --flag"))
	if code != toolMissingExitCode {
		t.Errorf("exit code = %d, want %d", code, toolMissingExitCode)
	}
	if !strings.Contains(out, "coi: coi-no-such-agent not found in this container") || !strings.Contains(out, "If codex is missing") || !strings.Contains(out, toolMissingHint) {
		t.Errorf("output = %q, want coi's hint", out)
	}
	if strings.Contains(out, "command not found") {
		t.Errorf("output = %q, want no bash error", out)
	}
}

// With the tool present the command runs as before, keeping its args and
// exit status.
func TestGuardToolInstalled_Present(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent"), []byte("#!/bin/sh\necho \"ran $*\"\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runGuarded(t, dir, guardToolInstalled("claude", "agent --verbose x"))
	if code != 3 || strings.TrimSpace(out) != "ran --verbose x" {
		t.Errorf("got %q (exit %d), want the tool's output and exit 3", out, code)
	}
}

// The check runs at launch, after the pre-launch steps: a binary they
// install passes.
func TestGuardToolInstalled_InstalledByPreLaunch(t *testing.T) {
	dir := t.TempDir()
	install := "printf '#!/bin/sh\\necho ran\\n' > agent && chmod +x agent; "
	out, code := runGuarded(t, dir, install+guardToolInstalled("claude", "agent"))
	if code != 0 || strings.TrimSpace(out) != "ran" {
		t.Errorf("got %q (exit %d), want the tool installed by pre-launch to run", out, code)
	}
}

// An absolute [tool] binary that is not executable counts as missing.
func TestGuardToolInstalled_AbsoluteNotExecutable(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runGuarded(t, dir, guardToolInstalled("claude", bin+" --verbose"))
	if code != toolMissingExitCode || !strings.Contains(out, "coi: "+bin+" not found") {
		t.Errorf("got %q (exit %d), want coi's hint and exit %d", out, code, toolMissingExitCode)
	}
}

// Against a real tmux: the hint survives the tmux wrapper's quoting, both
// for a new session and for a command sent into an existing one.
func TestGuardToolInstalled_Tmux(t *testing.T) {
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "c"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "TMUX_TMPDIR="+dir, "TMUX=")
	sh := func(script string) {
		t.Helper()
		c := exec.Command("bash", "-c", script)
		c.Env = env
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", script, err, out)
		}
	}
	t.Cleanup(func() {
		c := exec.Command("tmux", "kill-server")
		c.Env = env
		_ = c.Run()
	})

	guarded := guardToolInstalled("codex", "coi-no-such-agent")
	sh(buildTmuxNewSessionCmd(session.TmuxSessionName("c1"), dir, guarded, nil))
	waitForHints := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			c := exec.Command("tmux", "capture-pane", "-p", "-J", "-t", session.TmuxPaneTarget("c1"))
			c.Env = env
			out, _ := c.Output()
			if strings.Count(string(out), toolMissingHint) >= n {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("pane shows %d hint(s), want %d:\n%s", strings.Count(string(out), toolMissingHint), n, out)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitForHints(1)
	sh(tmuxSendKeysCmd("c1", guarded))
	waitForHints(2)
}
