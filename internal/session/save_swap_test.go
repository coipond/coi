package session

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// writeSavedCopy creates dir holding one marker file with the given content
func writeSavedCopy(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "history.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertSavedCopy fails unless dir holds the marker content and no swap
// sibling of dir is left behind
func assertSavedCopy(t *testing.T, dir, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, "history.jsonl"))
	if err != nil {
		t.Fatalf("saved copy missing: %v", err)
	}
	if string(got) != want {
		t.Errorf("saved copy = %q, want %q", got, want)
	}
	for _, suffix := range []string{completeSuffix, previousSuffix} {
		if pathExists(dir + suffix) {
			t.Errorf("%s left behind", filepath.Base(dir+suffix))
		}
	}
}

func TestFinishSavedConfigSwap_CrashStates(t *testing.T) {
	tests := []struct {
		name                  string
		live, complete, older string
		want                  string
	}{
		{name: "old moved aside, new not yet in place", complete: "new", older: "old", want: "new"},
		{name: "live missing, only new copy", complete: "new", want: "new"},
		{name: "live missing, only previous copy", older: "old", want: "old"},
		{name: "new in place, previous not yet removed", live: "new", older: "old", want: "new"},
		{name: "new complete, previous not yet moved aside", live: "old", complete: "new", want: "new"},
		{name: "clean", live: "old", want: "old"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			live := filepath.Join(t.TempDir(), ".claude")
			for dir, content := range map[string]string{live: tt.live, live + completeSuffix: tt.complete, live + previousSuffix: tt.older} {
				if content != "" {
					writeSavedCopy(t, dir, content)
				}
			}
			if err := finishSavedConfigSwap(live); err != nil {
				t.Fatalf("finishSavedConfigSwap: %v", err)
			}
			assertSavedCopy(t, live, tt.want)
		})
	}
}

func TestFinishSavedConfigSwap_NothingSaved(t *testing.T) {
	live := filepath.Join(t.TempDir(), ".claude")
	if err := finishSavedConfigSwap(live); err != nil {
		t.Fatalf("finishSavedConfigSwap: %v", err)
	}
	if pathExists(live) {
		t.Error("created a saved copy from nothing")
	}
}

// failingPullFake fails every config dir pull
type failingPullFake struct {
	container.ContainerManager
}

func (failingPullFake) PullDirectory(_, _ string) error {
	return errors.New("permission denied")
}

func TestSaveSessionData_KeepsCopyLeftByInterruptedSwap(t *testing.T) {
	sessions := t.TempDir()
	live := filepath.Join(sessions, "abc", ".claude")
	writeSavedCopy(t, live+completeSuffix, "new")
	writeSavedCopy(t, live+previousSuffix, "old")

	err := saveSessionData(failingPullFake{}, "coi-test", "abc", false, "", false, "/w", sessions, tool.NewClaude(), func(string) {})
	if err == nil {
		t.Fatal("saveSessionData succeeded with a failing pull")
	}
	assertSavedCopy(t, live, "new")
}

func TestSaveSessionData_ReplacesPreviousCopy(t *testing.T) {
	sessions := t.TempDir()
	live := filepath.Join(sessions, "abc", ".claude")
	writeSavedCopy(t, live, "old")
	writeSavedCopy(t, live+pullingSuffix, "partial")

	mgr := &savePullFake{files: map[string]string{"history.jsonl": "new"}}
	if err := saveSessionData(mgr, "coi-test", "abc", false, "", false, "/w", sessions, tool.NewClaude(), func(string) {}); err != nil {
		t.Fatalf("saveSessionData: %v", err)
	}
	assertSavedCopy(t, live, "new")
	if pathExists(live + pullingSuffix) {
		t.Error("pull staging left behind")
	}
}

func TestRecoverSavedSession(t *testing.T) {
	sessions := t.TempDir()
	live := filepath.Join(sessions, "abc", ".claude")
	writeSavedCopy(t, live+completeSuffix, "new")
	writeSavedCopy(t, live+previousSuffix, "old")

	if err := RecoverSavedSession(sessions, "abc", tool.NewClaude()); err != nil {
		t.Fatalf("RecoverSavedSession: %v", err)
	}
	assertSavedCopy(t, live, "new")
}

func TestFinishSavedConfigSwap_FailedRenameKeepsPreviousCopy(t *testing.T) {
	live := filepath.Join(t.TempDir(), ".claude")
	writeSavedCopy(t, live, "old")
	writeSavedCopy(t, live+completeSuffix, "new")
	orig := renameSavedCopy
	t.Cleanup(func() { renameSavedCopy = orig })
	renameSavedCopy = func(from, to string) error {
		if from == live+completeSuffix {
			return errors.New("injected rename failure")
		}
		return orig(from, to)
	}

	if err := finishSavedConfigSwap(live); err == nil {
		t.Fatal("finishSavedConfigSwap succeeded with a failing rename")
	}
	got, err := os.ReadFile(filepath.Join(live, "history.jsonl"))
	if err != nil {
		t.Fatalf("previous copy missing: %v", err)
	}
	if string(got) != "old" {
		t.Errorf("saved copy = %q, want %q", got, "old")
	}
}
