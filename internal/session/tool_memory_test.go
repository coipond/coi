package session

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// memoryExec records the command and user of each ExecCommand call.
type memoryExec struct {
	cmds  []string
	users []*int
	err   error
}

func (m *memoryExec) ExecCommand(cmd string, opts container.ExecCommandOptions) (string, error) {
	m.cmds = append(m.cmds, cmd)
	m.users = append(m.users, opts.User)
	return "", m.err
}

func mustTool(t *testing.T, name string) tool.Tool {
	t.Helper()
	ti, err := tool.Get(name)
	if err != nil {
		t.Fatalf("tool.Get(%q): %v", name, err)
	}
	return ti
}

func TestClearToolMemory_RemovesOnlyMemoryPaths(t *testing.T) {
	ti := mustTool(t, "claude")
	m := &memoryExec{}
	if err := clearToolMemory(m, "/home/code", ti, func(string) {}); err != nil {
		t.Fatalf("clearToolMemory: %v", err)
	}
	if len(m.cmds) != 1 {
		t.Fatalf("want one exec, got %d: %q", len(m.cmds), m.cmds)
	}
	cmd := m.cmds[0]
	if !strings.HasPrefix(cmd, "rm -rf -- ") {
		t.Errorf("want an rm -rf command, got %q", cmd)
	}
	for _, p := range ti.(tool.ToolWithMemoryPaths).MemoryPaths() {
		if !strings.Contains(cmd, " /home/code/.claude/"+p) {
			t.Errorf("command must remove %q: %q", p, cmd)
		}
	}
	tcf := ti.(tool.ToolWithConfigDirFiles)
	for _, keep := range append(tcf.EssentialConfigFiles(), tcf.SandboxSettingsFileName()) {
		if strings.Contains(cmd, "/.claude/"+keep+" ") || strings.HasSuffix(cmd, "/.claude/"+keep) {
			t.Errorf("command must keep %q: %q", keep, cmd)
		}
	}
	if strings.Contains(cmd, tcf.StateConfigFileName()) {
		t.Errorf("command must keep the state file %q: %q", tcf.StateConfigFileName(), cmd)
	}
	if u := m.users[0]; u == nil || *u != container.CodeUID {
		t.Errorf("must run as the code user (uid %d), got %v", container.CodeUID, u)
	}
}

func TestClearToolMemory_RootHomeRunsAsRoot(t *testing.T) {
	m := &memoryExec{}
	if err := clearToolMemory(m, "/root", mustTool(t, "codex"), func(string) {}); err != nil {
		t.Fatalf("clearToolMemory: %v", err)
	}
	if len(m.cmds) != 1 || !strings.Contains(m.cmds[0], " /root/.codex/sessions") {
		t.Fatalf("want codex sessions removed under /root, got %q", m.cmds)
	}
	if u := m.users[0]; u == nil || *u != 0 {
		t.Errorf("want uid 0 for /root, got %v", u)
	}
}

func TestClearToolMemory_ToolWithoutMemoryPathsIsNoop(t *testing.T) {
	m := &memoryExec{}
	if err := clearToolMemory(m, "/home/code", mustTool(t, "pi"), func(string) {}); err != nil {
		t.Fatalf("clearToolMemory: %v", err)
	}
	if len(m.cmds) != 0 {
		t.Errorf("want no exec for a tool without memory paths, got %q", m.cmds)
	}
}

func TestClearToolMemory_ExecErrorFails(t *testing.T) {
	m := &memoryExec{err: errors.New("exit status 1")}
	err := clearToolMemory(m, "/home/code", mustTool(t, "claude"), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "failed to clear claude memory") {
		t.Fatalf("want a clear-memory error, got %v", err)
	}
}

// memoryManager is a ContainerManager fake: ExecCommand answers the
// tool-session probe, pushes and chowns are recorded.
type memoryManager struct {
	container.ContainerManager
	probe  string
	execs  []string
	pushed []string
	chowns []string
}

func (m *memoryManager) ExecCommand(cmd string, _ container.ExecCommandOptions) (string, error) {
	m.execs = append(m.execs, cmd)
	return m.probe, nil
}

func (m *memoryManager) PushDirectory(src, dest string) error {
	m.pushed = append(m.pushed, "dir "+filepath.Base(src)+" -> "+dest)
	return nil
}

func (m *memoryManager) PushFile(src, dest string) error {
	m.pushed = append(m.pushed, "file "+filepath.Base(src)+" -> "+dest)
	return nil
}

func (m *memoryManager) Chown(path string, _, _ int) error {
	m.chowns = append(m.chowns, path)
	return nil
}

func TestToolSessionLive(t *testing.T) {
	ti := mustTool(t, "claude")
	cases := []struct {
		probe string
		err   error
		want  bool
	}{
		{"idle\n", nil, false},
		{"live\n", nil, true},
		{"", errors.New("exit status 1"), true},
	}
	for _, c := range cases {
		m := &memoryExec{err: c.err}
		r := &probeExec{memoryExec: m, out: c.probe}
		if got := toolSessionLive(r, "coi-abc-1", ti); got != c.want {
			t.Errorf("probe %q err %v: live = %v, want %v", c.probe, c.err, got, c.want)
		}
		if len(m.cmds) != 1 || !strings.Contains(m.cmds[0], "tmux has-session -t =coi-coi-abc-1") ||
			!strings.Contains(m.cmds[0], "pgrep -x claude") {
			t.Errorf("probe must check coi's tmux session and the tool process: %q", m.cmds)
		}
	}
}

// probeExec returns out from a memoryExec.
type probeExec struct {
	*memoryExec
	out string
}

func (p *probeExec) ExecCommand(cmd string, opts container.ExecCommandOptions) (string, error) {
	_, err := p.memoryExec.ExecCommand(cmd, opts)
	return p.out, err
}

func TestSetupStateFreshMemory(t *testing.T) {
	claude := mustTool(t, "claude")
	cases := []struct {
		name       string
		restarted  bool
		skipLaunch bool
		persistent bool
		fresh      bool
		named      string
		probe      string
		ti         tool.Tool
		want       bool
	}{
		{"restarted and fresh", true, true, true, true, "", "live", claude, true},
		{"running, no live tool (plain exit)", false, true, true, true, "", "idle", claude, true},
		{"running with a live tool", false, true, true, true, "", "live", claude, false},
		{"restarted, keep", true, true, true, false, "", "idle", claude, false},
		{"new container", false, false, true, true, "", "idle", claude, false},
		{"not persistent (running resume)", false, true, false, true, "", "idle", claude, false},
		{"explicit --container", false, true, true, true, "coi-x-1", "idle", claude, false},
		{"no tool", true, true, true, true, "", "idle", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &memoryManager{probe: c.probe}
			st := &setupState{
				restarted:  c.restarted,
				skipLaunch: c.skipLaunch,
				result:     &SetupResult{ContainerName: "coi-abc-1", Manager: m},
			}
			st.opts.FreshToolMemory = c.fresh
			st.opts.Persistent = c.persistent
			st.opts.ContainerName = c.named
			st.opts.Tool = c.ti
			if got := st.freshMemory(); got != c.want {
				t.Errorf("freshMemory() = %v, want %v", got, c.want)
			}
			st.freshMemory()
			if len(m.execs) > 1 {
				t.Errorf("the probe must run at most once, ran %d times", len(m.execs))
			}
		})
	}
}

// Resume on a reused container puts back only the memory paths: later
// settings, plugins and skills in the container stay.
func TestRestoreToolMemory_PushesOnlyMemoryPaths(t *testing.T) {
	sessions := t.TempDir()
	saved := filepath.Join(sessions, "s1", ".claude")
	for _, d := range []string{"projects/-workspace", "plugins", "skills"} {
		if err := os.MkdirAll(filepath.Join(saved, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"history.jsonl", "settings.json", "CLAUDE.md"} {
		if err := os.WriteFile(filepath.Join(saved, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m := &memoryManager{}
	if err := restoreToolMemory(m, "s1", "/home/code", sessions, mustTool(t, "claude"), func(string) {}); err != nil {
		t.Fatalf("restoreToolMemory: %v", err)
	}
	want := []string{
		"dir projects -> /home/code/.claude/projects",
		"file history.jsonl -> /home/code/.claude/history.jsonl",
	}
	if !reflect.DeepEqual(m.pushed, want) {
		t.Errorf("pushed = %q, want %q", m.pushed, want)
	}
	if !reflect.DeepEqual(m.chowns, []string{"/home/code/.claude/projects", "/home/code/.claude/history.jsonl"}) {
		t.Errorf("chowns = %q", m.chowns)
	}
}

func TestRestoreToolMemory_MissingSessionFails(t *testing.T) {
	err := restoreToolMemory(&memoryManager{}, "gone", "/home/code", t.TempDir(), mustTool(t, "claude"), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "no saved session data found for gone") {
		t.Fatalf("want a missing-session error, got %v", err)
	}
}
