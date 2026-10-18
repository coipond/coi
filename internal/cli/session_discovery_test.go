package cli

import (
	"errors"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// fakeDiscoveryManager records the one ExecArgsCapture call the in-container
// session lookup makes; every other method panics via the nil embed.
type fakeDiscoveryManager struct {
	container.ContainerManager

	out   string
	err   error
	calls int
	argv  []string
	opts  container.ExecCommandOptions
}

func (f *fakeDiscoveryManager) ExecArgsCapture(argv []string, opts container.ExecCommandOptions) (string, error) {
	f.calls++
	f.argv, f.opts = argv, opts
	return f.out, f.err
}

func TestDiscoverContainerSession_ResumesDiscoveredOpencodeSession(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "")
	mgr := &fakeDiscoveryManager{out: `[{"id":"ses_abc123"}]`}
	oc := tool.NewOpencode()
	env := map[string]string{"XDG_DATA_HOME": "/workspace/.local/share"}

	discoverContainerSession(mgr, oc, true, "/workspace", container.ExecCommandOptions{Cwd: "/workspace", Env: env})

	if mgr.calls != 1 {
		t.Fatalf("ExecArgsCapture calls = %d, want 1", mgr.calls)
	}
	if mgr.argv[0] != "timeout" || mgr.argv[2] != "opencode" || mgr.argv[3] != "db" {
		t.Errorf("argv = %q, want timeout N opencode db ...", mgr.argv)
	}
	if mgr.opts.Env["XDG_DATA_HOME"] != "/workspace/.local/share" {
		t.Errorf("lookup env = %v, want the tool's XDG_DATA_HOME", mgr.opts.Env)
	}
	if got := buildCLICommand("coi-id", true, false, t.TempDir(), "coi-id", oc); got != "opencode --session ses_abc123" {
		t.Errorf("buildCLICommand() = %q, want %q", got, "opencode --session ses_abc123")
	}
}

func TestDiscoverContainerSession_FallsBackToContinue(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "")
	for name, mgr := range map[string]*fakeDiscoveryManager{
		"no session":    {out: "[]"},
		"lookup failed": {out: `[{"id":"ses_abc123"}]`, err: errors.New("exit status 124")},
	} {
		t.Run(name, func(t *testing.T) {
			oc := tool.NewOpencode()
			discoverContainerSession(mgr, oc, true, "/workspace", container.ExecCommandOptions{})
			if got := buildCLICommand("coi-id", true, false, t.TempDir(), "coi-id", oc); got != "opencode --continue" {
				t.Errorf("buildCLICommand() = %q, want %q", got, "opencode --continue")
			}
		})
	}
}

func TestDiscoverContainerSession_Skipped(t *testing.T) {
	tests := []struct {
		name   string
		tool   tool.Tool
		resume bool
		dummy  string
	}{
		{"not resuming", tool.NewOpencode(), false, ""},
		{"dummy mode", tool.NewOpencode(), true, "1"},
		{"tool without container discovery", tool.NewClaude(), true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COI_USE_DUMMY", tt.dummy)
			mgr := &fakeDiscoveryManager{out: `[{"id":"ses_abc123"}]`}
			discoverContainerSession(mgr, tt.tool, tt.resume, "/workspace", container.ExecCommandOptions{})
			if mgr.calls != 0 {
				t.Errorf("ExecArgsCapture calls = %d, want 0", mgr.calls)
			}
		})
	}
}
