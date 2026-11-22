package session

import (
	"errors"
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

func TestSetupStateFreshMemory(t *testing.T) {
	claude := mustTool(t, "claude")
	cases := []struct {
		name      string
		restarted bool
		fresh     bool
		ti        tool.Tool
		want      bool
	}{
		{"restarted and fresh", true, true, claude, true},
		{"restarted, keep", true, false, claude, false},
		{"fresh but new or running container", false, true, claude, false},
		{"no tool", true, true, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := &setupState{restarted: c.restarted}
			st.opts.FreshToolMemory = c.fresh
			st.opts.Tool = c.ti
			if got := st.freshMemory(); got != c.want {
				t.Errorf("freshMemory() = %v, want %v", got, c.want)
			}
		})
	}
}
