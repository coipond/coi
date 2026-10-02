package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/container"
)

// runRenderedPreLaunch executes the real rendered script with bash and returns
// its combined output plus the exit code.
func runRenderedPreLaunch(t *testing.T, cmds []string, timeoutSec int) (string, int) {
	t.Helper()
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("timeout(1) not available")
	}
	script := filepath.Join(t.TempDir(), "pre-launch.sh")
	if err := os.WriteFile(script, []byte(renderUserPreLaunchScript(cmds, timeoutSec, 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("bash", script).CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

// Commands run in order with their output shown, each announced first; any
// shell syntax works (quotes, pipes, &&) because the command is quoted into
// the script rather than spliced into the tmux command line.
func TestUserPreLaunchScript_RunsCommandsInOrder(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "order")
	out, code := runRenderedPreLaunch(t, []string{
		"echo one >> " + marker,
		`echo "it's two" | tr a-z A-Z >> ` + marker + ` && echo two-ok`,
	}, 30)
	if code != 0 {
		t.Fatalf("script exited %d:\n%s", code, out)
	}
	got, _ := os.ReadFile(marker)
	if string(got) != "one\nIT'S TWO\n" {
		t.Errorf("commands ran out of order or mis-quoted: %q", got)
	}
	if !strings.Contains(out, "[coi] pre-launch: echo one") || !strings.Contains(out, "two-ok") {
		t.Errorf("each command should be announced and its output shown:\n%s", out)
	}
}

// A failing or timed-out command is reported and the script moves on and
// exits 0, so the tool always starts.
func TestUserPreLaunchScript_FailureAndTimeoutNeverBlock(t *testing.T) {
	dir := t.TempDir()
	after := filepath.Join(dir, "after")
	out, code := runRenderedPreLaunch(t, []string{
		"exit 3",
		"sleep 30",
		"touch " + after,
	}, 1)
	if code != 0 {
		t.Errorf("script must exit 0 so the tool starts, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "failed (exit 3); starting the tool anyway") {
		t.Errorf("failure should be reported:\n%s", out)
	}
	if !strings.Contains(out, "timed out after 1s; starting the tool anyway") {
		t.Errorf("timeout should be reported:\n%s", out)
	}
	if _, err := os.Stat(after); err != nil {
		t.Error("commands after a failure/timeout must still run")
	}
}

// withUserPreLaunch leaves the command alone when nothing is configured, and
// otherwise prefixes a fixed, quote-free path — the commands themselves never
// enter the tmux command line.
func TestWithUserPreLaunch(t *testing.T) {
	if got := withUserPreLaunch(nil, nil, "claude --verbose"); got != "claude --verbose" {
		t.Errorf("no pre_launch: got %q", got)
	}
	rec := &preLaunchRecorder{}
	got := withUserPreLaunch(rec, []string{`claude update; echo "done"`}, "claude --verbose")
	if got != "trap : INT; bash "+userPreLaunchScriptPath+"; claude --verbose" {
		t.Errorf("prefixed command = %q", got)
	}
	if strings.Contains(got, "update") {
		t.Error("the user's command must not be spliced into the tool command line")
	}
	if rec.path != userPreLaunchScriptPath || rec.uid != 0 || rec.mode != "0755" ||
		!strings.Contains(rec.content, `coi_pre_launch 'claude update; echo "done"'`) {
		t.Errorf("script not installed root-owned with the command: %+v", rec)
	}
}

// A script that can't be written skips the pre-launch step; the tool starts.
func TestWithUserPreLaunch_WriteFailureStillStartsTool(t *testing.T) {
	rec := &preLaunchRecorder{failCreate: true}
	if got := withUserPreLaunch(rec, []string{"claude update"}, "claude --verbose"); got != "claude --verbose" {
		t.Errorf("on write failure the tool command must be unchanged, got %q", got)
	}
}

// preLaunchRecorder is a ContainerManager that records the pre-launch script
// write (embedding the interface leaves every other method unimplemented).
type preLaunchRecorder struct {
	container.ContainerManager
	path, content, mode string
	uid                 int
	failCreate          bool
}

func (r *preLaunchRecorder) ExecCommand(string, container.ExecCommandOptions) (string, error) {
	return "", nil
}

func (r *preLaunchRecorder) CreateFileWithOwner(path, content string, uid, _ int, mode string) error {
	if r.failCreate {
		return errors.New("write failed")
	}
	r.path, r.content, r.uid, r.mode = path, content, uid, mode
	return nil
}

// A command that ignores TERM still can't hold the tool up: timeout escalates
// to KILL after the grace period. (With --foreground, a process the command
// started in the background may outlive the timeout — the accepted trade-off
// for keeping Ctrl+C and the terminal working; see renderUserPreLaunchScript.)
func TestUserPreLaunchScript_TimeoutKillsStubbornCommand(t *testing.T) {
	dir := t.TempDir()
	after := filepath.Join(dir, "after")
	start := time.Now()
	out, code := runRenderedPreLaunch(t, []string{
		"trap '' TERM; exec sleep 60",
		"touch " + after,
	}, 1)
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("a TERM-ignoring command blocked for %v", elapsed)
	}
	if code != 0 || !strings.Contains(out, "timed out after 1s") {
		t.Errorf("timeout should be reported and the script exit 0 (code %d):\n%s", code, out)
	}
	if _, err := os.Stat(after); err != nil {
		t.Error("the next command must still run")
	}
}

// runInTerminal runs `bash -c 'trap : INT; bash <script>; echo TOOLSTART'` —
// the shape of the real launch — inside a pseudo-terminal (util-linux
// script(1)), optionally typing Ctrl+C after ctrlCAfter, and returns the
// output and how long until TOOLSTART appeared.
func runInTerminal(t *testing.T, cmds []string, ctrlCAfter time.Duration) (string, time.Duration) {
	t.Helper()
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) not available")
	}
	pl := filepath.Join(t.TempDir(), "pre-launch.sh")
	if err := os.WriteFile(pl, []byte(renderUserPreLaunchScript(cmds, 300, 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("script", "-qfec", "bash -c 'trap : INT; bash "+pl+"; echo TOOLSTART'", "/dev/null")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if ctrlCAfter > 0 {
		time.Sleep(ctrlCAfter)
		_, _ = stdin.Write([]byte{0x03})
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("launch did not finish in 30s:\n%s", out.String())
	}
	_ = stdin.Close()
	return out.String(), time.Since(start)
}

// Ctrl+C during a pre_launch command skips it and the remaining commands, and
// the tool starts right away. (Without --foreground the command sat in a
// background process group, Ctrl+C never reached it, and the user waited it
// out — found in review of #861.)
func TestUserPreLaunch_CtrlCSkipsRemainingCommands(t *testing.T) {
	out, took := runInTerminal(t, []string{"sleep 20", "echo SECOND-RAN"}, 1500*time.Millisecond)
	if !strings.Contains(out, "TOOLSTART") {
		t.Fatalf("the tool should start after Ctrl+C:\n%s", out)
	}
	if took > 10*time.Second {
		t.Errorf("Ctrl+C should end the slow command immediately; tool started after %v", took)
	}
	if strings.Contains(out, "SECOND-RAN") {
		t.Errorf("Ctrl+C should skip the remaining commands:\n%s", out)
	}
}

// A pre_launch command can set terminal modes without being stopped (in a
// background process group tcsetattr raised SIGTTOU and froze it until the
// timeout).
func TestUserPreLaunch_TerminalModesWork(t *testing.T) {
	out, took := runInTerminal(t, []string{"stty sane </dev/tty && echo STTY-OK"}, 0)
	if !strings.Contains(out, "STTY-OK") || !strings.Contains(out, "TOOLSTART") {
		t.Errorf("stty should succeed and the tool start:\n%s", out)
	}
	if took > 10*time.Second {
		t.Errorf("setting terminal modes should not stall; took %v", took)
	}
}

// A pre-launch command gets no terminal input (stdin is /dev/null), so a
// command that tries to read can't stall the launch.
func TestUserPreLaunchScript_CommandsGetNoInput(t *testing.T) {
	out, code := runRenderedPreLaunch(t, []string{`read -r x; echo "read-rc=$?"`}, 30)
	if code != 0 || !strings.Contains(out, "read-rc=1") {
		t.Errorf("a read should get EOF immediately (code %d):\n%s", code, out)
	}
}
