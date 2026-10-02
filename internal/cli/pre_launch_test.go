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

// A command that ignores TERM, or leaves a child process behind, still can't
// hold the tool up: timeout escalates to KILL and covers the whole process
// group (review of #861).
func TestUserPreLaunchScript_TimeoutKillsStubbornCommandAndChildren(t *testing.T) {
	dir := t.TempDir()
	after := filepath.Join(dir, "after")
	pidFile := filepath.Join(dir, "child.pid")
	start := time.Now()
	out, code := runRenderedPreLaunch(t, []string{
		"trap '' TERM; sleep 60 & echo $! > " + pidFile + "; sleep 60; wait",
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
	pid, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("child pid not recorded: %v", err)
	}
	if childAlive(strings.TrimSpace(string(pid))) {
		_ = exec.Command("kill", "-9", strings.TrimSpace(string(pid))).Run()
		t.Error("the timed-out command's child process must be killed too")
	}
}

// childAlive reports whether pid is a live (non-zombie) process.
func childAlive(pid string) bool {
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return false
	}
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || !strings.HasPrefix(strings.TrimSpace(s[i+1:]), "Z")
}

// A pre-launch command gets no terminal input (stdin is /dev/null), so a
// command that tries to read can't stall the launch.
func TestUserPreLaunchScript_CommandsGetNoInput(t *testing.T) {
	out, code := runRenderedPreLaunch(t, []string{`read -r x; echo "read-rc=$?"`}, 30)
	if code != 0 || !strings.Contains(out, "read-rc=1") {
		t.Errorf("a read should get EOF immediately (code %d):\n%s", code, out)
	}
}
