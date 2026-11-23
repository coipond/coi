package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// savePullFake pulls a config dir holding the given files (relative path to
// content), as `incus file pull -r` would.
type savePullFake struct {
	container.ContainerManager
	files map[string]string
}

func (f *savePullFake) PullDirectory(_, localPath string) error {
	for name, content := range f.files {
		p := filepath.Join(localPath, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func saveOpencodeSession(t *testing.T, toolName string) string {
	t.Helper()
	tl, err := tool.Get(toolName)
	if err != nil {
		t.Fatal(err)
	}
	sessions := t.TempDir()
	mgr := &savePullFake{files: map[string]string{
		"opencode.json": `{"permission":{"*":"allow"}}`,
		"service.json":  `{"password":"secret"}`,
	}}
	if err := saveSessionData(mgr, "coi-test", "abc", false, "", false, "/w", sessions, tl, func(string) {}, nil); err != nil {
		t.Fatalf("saveSessionData: %v", err)
	}
	return filepath.Join(sessions, "abc", tl.ConfigDirName())
}

func TestSaveSessionData_Opencode2DropsServiceJSON(t *testing.T) {
	saved := saveOpencodeSession(t, "opencode2")
	if _, err := os.Stat(filepath.Join(saved, "service.json")); !os.IsNotExist(err) {
		t.Errorf("service.json was saved (stat err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(saved, "opencode.json")); err != nil {
		t.Errorf("opencode.json was not saved: %v", err)
	}
}

func TestSaveSessionData_OpencodeKeepsConfigDir(t *testing.T) {
	saved := saveOpencodeSession(t, "opencode")
	for _, f := range []string{"opencode.json", "service.json"} {
		if _, err := os.Stat(filepath.Join(saved, f)); err != nil {
			t.Errorf("%s was not saved: %v", f, err)
		}
	}
}

// boundedPullFake times out after pulling part of the config dir, as
// PullDirectoryBounded does on a stalled pull.
type boundedPullFake struct {
	container.ContainerManager
	pulls int
}

func (f *boundedPullFake) PullDirectoryBounded(_, localPath string, _ time.Duration, _ func(string)) error {
	f.pulls++
	if err := os.MkdirAll(localPath, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(localPath, "history.jsonl"), []byte("partial"), 0o600); err != nil {
		return err
	}
	return fmt.Errorf("%w: stalled on /home/code/.claude/fifo", container.ErrPullTimedOut)
}

// A timed-out fallback pull keeps what was pulled and is not retried.
func TestSaveSessionData_TimedOutPullKeepsPulled(t *testing.T) {
	sessions := t.TempDir()
	mgr := &boundedPullFake{}
	var logs []string
	if err := saveSessionData(mgr, "coi-test", "abc", false, "", false, "/w", sessions, tool.NewClaude(), func(m string) { logs = append(logs, m) }, nil); err != nil {
		t.Fatalf("saveSessionData: %v", err)
	}
	assertSavedCopy(t, filepath.Join(sessions, "abc", ".claude"), "partial")
	if mgr.pulls != 1 {
		t.Errorf("pulls = %d, want 1", mgr.pulls)
	}
	if got := strings.Join(logs, "\n"); !strings.Contains(got, "timed out") || !strings.Contains(got, "/home/code/.claude/fifo") {
		t.Errorf("logs = %q, want the timeout and the stalled path", got)
	}
}
