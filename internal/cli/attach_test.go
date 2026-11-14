package cli

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

func TestSelectAttachTarget_IgnoresStopped(t *testing.T) {
	target, running := selectAttachTarget([]ContainerInfo{
		{Name: "coi-abc12345-1", Status: "STOPPED"},
		{Name: "coi-abc12345-2", Status: "RUNNING"},
	})
	if target != "coi-abc12345-2" {
		t.Errorf("target = %q, want coi-abc12345-2", target)
	}
	if !slices.Equal(running, []string{"coi-abc12345-2"}) {
		t.Errorf("running = %v, want [coi-abc12345-2]", running)
	}
}

func TestSelectAttachTarget(t *testing.T) {
	tests := []struct {
		name        string
		containers  []ContainerInfo
		wantTarget  string
		wantRunning []string
	}{
		{"none", nil, "", nil},
		{"only stopped", []ContainerInfo{
			{Name: "coi-abc12345-1", Status: "STOPPED"},
			{Name: "coi-abc12345-2", Status: "STOPPED"},
		}, "", nil},
		{"several running", []ContainerInfo{
			{Name: "coi-abc12345-1", Status: "RUNNING"},
			{Name: "coi-abc12345-2", Status: "STOPPED"},
			{Name: "coi-abc12345-3", Status: "RUNNING"},
		}, "", []string{"coi-abc12345-1", "coi-abc12345-3"}},
		{"prefix not at start", []ContainerInfo{
			{Name: "xcoi-aaaa", Status: "RUNNING"},
		}, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, running := selectAttachTarget(tt.containers)
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
		err := attachToContainer(mgr, "coi-abc12345-1")
		var ece *ExitCodeError
		if !errors.As(err, &ece) || ece.Code != ExitGeneric {
			t.Errorf("running=%v: attachToContainer = %v, want an ExitCodeError with code %d", running, err, ExitGeneric)
		}
	}
}

func TestAttachToContainer_SignalExitIsNotAnError(t *testing.T) {
	mgr := &fakeAttachManager{execErr: errors.New("exit status 130"), running: true}
	if err := attachToContainer(mgr, "coi-abc12345-1"); err != nil {
		t.Errorf("attachToContainer = %v, want nil after Ctrl+C", err)
	}
}
