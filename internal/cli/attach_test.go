package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

func TestSelectAttachTarget(t *testing.T) {
	tests := []struct {
		name        string
		names       []string
		wantTarget  string
		wantRunning []string
	}{
		{"none", nil, "", nil},
		{"one", []string{"coi-abc12345-2"}, "coi-abc12345-2", []string{"coi-abc12345-2"}},
		{"several", []string{"coi-abc12345-1", "coi-abc12345-3"}, "", []string{"coi-abc12345-1", "coi-abc12345-3"}},
		{"prefix not at start", []string{"xcoi-aaaa"}, "", nil},
		{"one with a foreign one", []string{"xcoi-aaaa", "coi-abc12345-1"}, "coi-abc12345-1", []string{"coi-abc12345-1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COI_CONTAINER_PREFIX", "")
			target, running := selectAttachTarget(tt.names)
			if target != tt.wantTarget {
				t.Errorf("target = %q, want %q", target, tt.wantTarget)
			}
			if !slices.Equal(running, tt.wantRunning) {
				t.Errorf("running = %v, want %v", running, tt.wantRunning)
			}
		})
	}
}

func TestAttach_RejectsUsageErrorsBeforeIncus(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"name with --slot", []string{"attach", "--slot", "2", "coi-abc12345-1"}, "not both"},
		{"negative --slot", []string{"attach", "--slot", "-1"}, "invalid --slot -1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := fakeKillIncus(t, "", "coi-abc12345-1")

			err := executeWithProfiles(t, nil, "", tt.args...)
			var ece *ExitCodeError
			if !errors.As(err, &ece) || ece.Code != ExitUsage {
				t.Fatalf("coi %v = %v, want an ExitCodeError with code %d", tt.args, err, ExitUsage)
			}
			if !strings.Contains(ece.Message, tt.want) {
				t.Errorf("message = %q, want it to contain %q", ece.Message, tt.want)
			}
			if b, _ := os.ReadFile(logPath); len(b) > 0 {
				t.Errorf("incus called before the usage error:\n%s", b)
			}
		})
	}
}

func TestAttach_RejectsExtraArgs(t *testing.T) {
	logPath := fakeKillIncus(t, "", "coi-abc12345-1")

	err := executeWithProfiles(t, nil, "", "attach", "coi-abc12345-1", "coi-abc12345-2")
	if err == nil || !strings.Contains(err.Error(), "accepts at most 1 arg") {
		t.Fatalf("coi attach <two names> = %v, want an argument count error", err)
	}
	if b, _ := os.ReadFile(logPath); len(b) > 0 {
		t.Errorf("incus called before the argument error:\n%s", b)
	}
}

// fakeAttachIncus puts an incus script on PATH whose `incus list --format=csv
// --columns=ns` prints rows, on which the code user has UID 1000 and no
// running container has an alias. It logs every call and returns the log path.
func fakeAttachIncus(t *testing.T, rows string) string {
	t.Helper()
	t.Setenv("COI_CONTAINER_PREFIX", "")
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
  *"--format=csv --columns=ns"*) printf '` + rows + `' ;;
  *"--format=json"*) echo '[]' ;;
  *"id -u"*) echo 1000 ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// captureOutput returns what fn writes to *f (os.Stdout or os.Stderr).
func captureOutput(t *testing.T, f **os.File, fn func()) string {
	t.Helper()
	old := *f
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	*f = wp
	defer func() { *f = old }()

	fn()

	_ = wp.Close()
	*f = old
	data, _ := io.ReadAll(rp)
	return string(data)
}

// tmuxAttachCalls returns the logged `tmux attach` execs.
func tmuxAttachCalls(t *testing.T, logPath string) []string {
	t.Helper()
	b, _ := os.ReadFile(logPath)
	var calls []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "tmux attach") {
			calls = append(calls, line)
		}
	}
	return calls
}

const stoppedAndRunningRows = `coi-abc12345-1,STOPPED\ncoi-abc12345-2,RUNNING\n`

func TestAttach_IgnoresStopped(t *testing.T) {
	logPath := fakeAttachIncus(t, stoppedAndRunningRows)

	if err := executeWithProfiles(t, nil, "", "attach"); err != nil {
		t.Fatalf("coi attach = %v", err)
	}
	calls := tmuxAttachCalls(t, logPath)
	if len(calls) != 1 || !strings.Contains(calls[0], "exec coi-abc12345-2 ") {
		t.Errorf("tmux attach execs = %q, want one in coi-abc12345-2", calls)
	}
}

func TestAttach_StoppedNameIsNotRunning(t *testing.T) {
	logPath := fakeAttachIncus(t, stoppedAndRunningRows)

	err := executeWithProfiles(t, nil, "", "attach", "coi-abc12345-1")
	if err == nil || !strings.Contains(err.Error(), "not found or not running") {
		t.Fatalf("coi attach coi-abc12345-1 = %v, want not found or not running", err)
	}
	if calls := tmuxAttachCalls(t, logPath); len(calls) > 0 {
		t.Errorf("tmux attach exec on a stopped container: %q", calls)
	}
}

func TestAttach_OnlyStoppedHasNoActiveSessions(t *testing.T) {
	logPath := fakeAttachIncus(t, `coi-abc12345-1,STOPPED\ncoi-abc12345-2,STOPPED\n`)

	var err error
	out := captureOutput(t, &os.Stdout, func() {
		err = executeWithProfiles(t, nil, "", "attach")
	})
	if err != nil {
		t.Fatalf("coi attach = %v", err)
	}
	if !strings.Contains(out, "No active sessions") || strings.Contains(out, "Active sessions:") {
		t.Errorf("stdout = %q, want No active sessions", out)
	}
	if calls := tmuxAttachCalls(t, logPath); len(calls) > 0 {
		t.Errorf("tmux attach exec with no running container: %q", calls)
	}
}

// fakeAttachManager is a container.ContainerManager double whose tmux attach
// fails with execErr.
type fakeAttachManager struct {
	container.ContainerManager
	execErr error
	running bool
}

func (f *fakeAttachManager) GetWorkspacePath() string { return "/workspace" }

func (f *fakeAttachManager) ExecArgsCapture(_ []string, _ container.ExecCommandOptions) (string, error) {
	return "1000\n", nil
}

func (f *fakeAttachManager) ExecArgs(_ []string, _ container.ExecCommandOptions) error {
	return f.execErr
}

func (f *fakeAttachManager) Running() (bool, error) { return f.running, nil }

func TestAttachToContainer_TmuxAttachFailureExitsNonZero(t *testing.T) {
	for _, running := range []bool{true, false} {
		mgr := &fakeAttachManager{execErr: errors.New("exit status 1"), running: running}
		var err error
		stderr := captureOutput(t, &os.Stderr, func() {
			err = attachToContainer(mgr, "coi-abc12345-1")
		})
		var ece *ExitCodeError
		if !errors.As(err, &ece) || ece.Code != ExitGeneric {
			t.Errorf("running=%v: attachToContainer = %v, want an ExitCodeError with code %d", running, err, ExitGeneric)
		}
		if !strings.Contains(stderr, "No tmux session found") {
			t.Errorf("running=%v: stderr = %q, want the no-session hint", running, stderr)
		}
		hint := strings.Contains(stderr, "still running") && strings.Contains(stderr, "coi attach coi-abc12345-1 --bash")
		if hint != running {
			t.Errorf("running=%v: stderr = %q, want the still-running --bash hint only when running", running, stderr)
		}
	}
}

func TestAttachToContainer_SignalExitIsNotAnError(t *testing.T) {
	mgr := &fakeAttachManager{execErr: errors.New("exit status 130"), running: true}
	if err := attachToContainer(mgr, "coi-abc12345-1"); err != nil {
		t.Errorf("attachToContainer = %v, want nil after Ctrl+C", err)
	}
}
