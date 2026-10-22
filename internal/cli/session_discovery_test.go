package cli

import (
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
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

	// execCommands records ExecCommand calls (the tmux prep script); each
	// one reports a newly created tmux session.
	execCommands []string
}

func (f *fakeDiscoveryManager) ExecCommand(cmd string, _ container.ExecCommandOptions) (string, error) {
	f.execCommands = append(f.execCommands, cmd)
	return tmuxPrepCreated + "\n", nil
}

func (f *fakeDiscoveryManager) ExecArgsCapture(argv []string, opts container.ExecCommandOptions) (string, error) {
	f.calls++
	// Clone Env: the caller keeps mutating its map after the lookup.
	f.argv, f.opts = argv, opts
	f.opts.Env = maps.Clone(opts.Env)
	return f.out, f.err
}

func TestDiscoverContainerSession_ResumesDiscoveredOpencodeSession(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "")
	mgr := &fakeDiscoveryManager{out: `[{"id":"ses_abc123"}]`}
	oc := tool.NewOpencode()
	env := map[string]string{"HOME": "/home/code"}

	discoverContainerSession(mgr, oc, true, "/workspace", container.ExecCommandOptions{Cwd: "/workspace", Env: env})

	if mgr.calls != 1 {
		t.Fatalf("ExecArgsCapture calls = %d, want 1", mgr.calls)
	}
	if mgr.argv[0] != "timeout" || mgr.argv[2] != "opencode" || mgr.argv[3] != "db" {
		t.Errorf("argv = %q, want timeout N opencode db ...", mgr.argv)
	}
	if mgr.opts.Env["HOME"] != "/home/code" {
		t.Errorf("lookup env = %v, want the launch env's HOME", mgr.opts.Env)
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

// The launch paths must run the lookup with the launch env before they
// build the command, so a resume reaches opencode as --session <id>.
func TestPrepareLaunch_ResumesDiscoveredOpencodeSession(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "")
	for _, mode := range []string{"direct", "tmux"} {
		t.Run(mode, func(t *testing.T) {
			mgr := &fakeDiscoveryManager{out: `[{"id":"ses_abc123"}]`}
			a := &App{cfg: &config.Config{}}
			result := &session.SetupResult{ContainerName: "coi-test-1", Manager: mgr, ContainerWorkspacePath: "/workspace"}
			env := map[string]string{"HOME": "/home/code"}
			uid := 1000
			oc := tool.NewOpencode()

			var cmd string
			if mode == "direct" {
				d, err := a.prepareDirect(result, env, &uid, "coi-id", true, false, t.TempDir(), "coi-id", oc)
				if err != nil {
					t.Fatalf("prepareDirect() error = %v", err)
				}
				cmd = d.cmd
			} else {
				l, err := a.prepareTmux(result, env, &uid, "coi-id", true, false, t.TempDir(), "coi-id", oc)
				if err != nil {
					t.Fatalf("prepareTmux() error = %v", err)
				}
				cmd = l.cliCmd
				if len(mgr.execCommands) != 1 || !strings.Contains(mgr.execCommands[0], "opencode --session ses_abc123") {
					t.Errorf("tmux session command = %q, want it to launch opencode --session ses_abc123", mgr.execCommands)
				}
			}

			if cmd != "opencode --session ses_abc123" {
				t.Errorf("launch command = %q, want %q", cmd, "opencode --session ses_abc123")
			}
			if mgr.calls != 1 {
				t.Fatalf("lookup calls = %d, want 1", mgr.calls)
			}
			if got := mgr.opts.Env["HOME"]; got != "/home/code" {
				t.Errorf("lookup HOME = %q, want %q", got, "/home/code")
			}
			if mgr.opts.Cwd != "/workspace" || mgr.opts.User == nil || *mgr.opts.User != uid {
				t.Errorf("lookup cwd/user = %q/%v, want /workspace as uid %d", mgr.opts.Cwd, mgr.opts.User, uid)
			}
		})
	}
}

func TestPrepareLaunch_NewSessionSkipsLookup(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "")
	mgr := &fakeDiscoveryManager{out: `[{"id":"ses_abc123"}]`}
	a := &App{cfg: &config.Config{}}
	result := &session.SetupResult{ContainerName: "coi-test-1", Manager: mgr}
	uid := 1000

	d, err := a.prepareDirect(result, map[string]string{}, &uid, "coi-id", false, false, t.TempDir(), "", tool.NewOpencode())
	if err != nil {
		t.Fatalf("prepareDirect() error = %v", err)
	}
	if d.cmd != "opencode" || mgr.calls != 0 {
		t.Errorf("launch command = %q with %d lookups, want %q with none", d.cmd, mgr.calls, "opencode")
	}
}
