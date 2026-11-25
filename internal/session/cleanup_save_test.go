package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/logger"
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

// boundedPullFake stops after pulling part of the config dir, as
// PullDirectoryBounded does on a stalled pull.
type boundedPullFake struct {
	container.ContainerManager
	pulls int
}

func (f *boundedPullFake) PullDirectoryBounded(_, localPath string, _ time.Duration, _, _ func(string)) error {
	f.pulls++
	if err := os.MkdirAll(localPath, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(localPath, "history.jsonl"), []byte("partial"), 0o600); err != nil {
		return err
	}
	return fmt.Errorf("%w: stalled on /home/code/.claude/fifo", container.ErrPullStopped)
}

// A stopped fallback pull keeps what was pulled and is not retried.
func TestSaveSessionData_StoppedPullKeepsPulled(t *testing.T) {
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
	if got := strings.Join(logs, "\n"); !strings.Contains(got, "pull stopped") || !strings.Contains(got, "/home/code/.claude/fifo") {
		t.Errorf("logs = %q, want the stop and the stalled path", got)
	}
}

// vanishedEntryFake fails like a bounded pull whose entry vanished mid-pull.
type vanishedEntryFake struct {
	container.ContainerManager
}

func (vanishedEntryFake) PullDirectoryBounded(_, _ string, _ time.Duration, _, _ func(string)) error {
	return errors.New("Error: not found: exit status 1")
}

// A bounded pull's "not found" for one entry is a failed save, not "no
// config dir" (which would skip the save without a warning).
func TestSaveSessionData_BoundedEntryNotFoundFailsSave(t *testing.T) {
	err := saveSessionData(vanishedEntryFake{}, "coi-test", "abc", false, "", false, "/w", t.TempDir(), tool.NewClaude(), func(string) {}, nil)
	if err == nil {
		t.Fatal("saveSessionData succeeded; want the pull error")
	}
}

// Skipped special files reach the session log.
func TestSessionDebug_WritesSessionLog(t *testing.T) {
	sl := logger.New("coi-test", t.TempDir())
	sessionDebug(CleanupOptions{SessionLogger: sl})("Skipping special file /home/code/.claude/fifo (type p)")
	if err := sl.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(sl.OutPath())
	if err != nil || !strings.Contains(string(b), "[cleanup] Skipping special file /home/code/.claude/fifo") {
		t.Errorf("session log = %q, %v", b, err)
	}
	sessionDebug(CleanupOptions{})("no session log: no panic")
}
