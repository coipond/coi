package session

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// fakeDirProbe is a minimal containerCommandRunner: it records the command and
// returns success/failure to stand in for the marker-check's exit status.
type fakeDirProbe struct {
	seeded bool
	gotCmd string
}

func (f *fakeDirProbe) ExecCommand(cmd string, _ container.ExecCommandOptions) (string, error) {
	f.gotCmd = cmd
	if f.seeded {
		return "", nil
	}
	return "", fmt.Errorf("exit status 1") // marker absent
}

// toolConfigSeeded must key off the tool's ESSENTIAL config files, not the
// dir's existence or content — the base image pre-creates the config dirs and
// agent installers can leave unrelated files in them, so an existence/content
// check would wrongly report a tool already-configured and skip reuse-seeding
// (#708 follow-up).
func TestToolConfigSeeded(t *testing.T) {
	c, err := tool.Get("claude")
	if err != nil {
		t.Fatalf("tool.Get: %v", err)
	}
	tcf, ok := c.(tool.ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("claude should implement ToolWithConfigDirFiles")
	}

	t.Run("seeded when an essential file exists", func(t *testing.T) {
		fp := &fakeDirProbe{seeded: true}
		if !toolConfigSeeded(fp, "/home/code", tcf) {
			t.Error("want seeded=true when an essential config file exists")
		}
		// It must test the tool's essential files (not `test -d`/`ls -A`, which
		// the pre-created dirs / installer files would fool).
		for _, f := range tcf.EssentialConfigFiles() {
			if !strings.Contains(fp.gotCmd, "test -f /home/code/.claude/"+f) {
				t.Errorf("probe must test essential file %q, got %q", f, fp.gotCmd)
			}
		}
		if strings.Contains(fp.gotCmd, "test -d") || strings.Contains(fp.gotCmd, "ls -A") {
			t.Errorf("probe must not be a dir existence/content check: %q", fp.gotCmd)
		}
	})

	t.Run("not seeded when no essential file exists", func(t *testing.T) {
		fa := &fakeDirProbe{seeded: false}
		if toolConfigSeeded(fa, "/home/code", tcf) {
			t.Error("want seeded=false when no essential config file is present")
		}
	})
}

// stoppedLeftoverFake is a stopped container whose config dir holds files; it
// records the pull and delete calls in order
type stoppedLeftoverFake struct {
	container.ContainerManager
	files   map[string]string
	pullErr error
	calls   []string
}

func (f *stoppedLeftoverFake) Exists() (bool, error)  { return true, nil }
func (f *stoppedLeftoverFake) Running() (bool, error) { return false, nil }

func (f *stoppedLeftoverFake) PullDirectory(containerPath, localPath string) error {
	f.calls = append(f.calls, "pull")
	if f.pullErr != nil {
		return f.pullErr
	}
	return (&savePullFake{files: f.files}).PullDirectory(containerPath, localPath)
}

func (f *stoppedLeftoverFake) Delete(_ bool) error {
	f.calls = append(f.calls, "delete")
	return nil
}

// writeLeftoverSession saves session id with a saved config dir holding
// content and metadata naming containerName, saved at savedAt
func writeLeftoverSession(t *testing.T, sessions, id, containerName, savedAt, content string) {
	t.Helper()
	writeSavedCopy(t, filepath.Join(sessions, id, ".claude"), content)
	m := SessionMetadata{SessionID: id, ContainerName: containerName, ProfileName: "work", Workspace: "/w", SavedAt: savedAt}
	if err := saveMetadata(filepath.Join(sessions, id, "metadata.json"), m); err != nil {
		t.Fatal(err)
	}
}

// reconcileStoppedLeftover runs the reconcile phase of an ephemeral launch
// resuming resumeID over mgr
func reconcileStoppedLeftover(sessions, resumeID string, mgr container.ContainerManager) error {
	st := &setupState{
		opts:   SetupOptions{ResumeFromID: resumeID, SessionsDir: sessions, Tool: tool.NewClaude(), Logger: func(string) {}},
		result: &SetupResult{Manager: mgr, ContainerName: "coi-leftover-1"},
	}
	_, err := st.phaseReconcileExisting(context.Background())
	return err
}

func TestPhaseReconcileExisting_ResumeSavesStoppedLeftoverBeforeDelete(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "sessions-claude")
	writeLeftoverSession(t, sessions, "abc", "coi-leftover-1", "2026-11-22T10:00:00Z", "old")
	mgr := &stoppedLeftoverFake{files: map[string]string{"history.jsonl": "latest"}}

	if err := reconcileStoppedLeftover(sessions, "abc", mgr); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(mgr.calls, ","); got != "pull,delete" {
		t.Errorf("calls = %s, want pull,delete", got)
	}
	assertSavedCopy(t, filepath.Join(sessions, "abc", ".claude"), "latest")
	m, err := LoadSessionMetadata(filepath.Join(sessions, "abc", "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if m.ProfileName != "work" || m.Workspace != "/w" || m.ContainerName != "coi-leftover-1" {
		t.Errorf("metadata = %+v, want the session's profile, workspace and container kept", m)
	}
}

func TestPhaseReconcileExisting_ResumeSkipsAnotherSessionsLeftover(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "sessions-claude")
	// The newer session's id sorts first, so a last-listed-wins pick fails.
	writeLeftoverSession(t, sessions, "zzz", "coi-leftover-1", "2026-11-22T10:00:00Z", "old")
	writeLeftoverSession(t, sessions, "aaa", "coi-leftover-1", "2026-11-22T11:00:00Z", "other")
	mgr := &stoppedLeftoverFake{files: map[string]string{"history.jsonl": "latest"}}

	if err := reconcileStoppedLeftover(sessions, "zzz", mgr); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(mgr.calls, ","); got != "delete" {
		t.Errorf("calls = %s, want delete only", got)
	}
	assertSavedCopy(t, filepath.Join(sessions, "zzz", ".claude"), "old")
}

func TestPhaseReconcileExisting_ResumeSkipsAnotherToolsLeftover(t *testing.T) {
	// Container names have no tool part; "abc" also covers the same id.
	for _, id := range []string{"def", "abc"} {
		t.Run("codex session "+id, func(t *testing.T) {
			sessions := filepath.Join(t.TempDir(), "sessions-claude")
			writeLeftoverSession(t, sessions, "abc", "coi-leftover-1", "2026-11-22T10:00:00Z", "old")
			writeLeftoverSession(t, filepath.Join(filepath.Dir(sessions), "sessions-codex"), id, "coi-leftover-1", "2026-11-22T11:00:00Z", "other")
			mgr := &stoppedLeftoverFake{files: map[string]string{"history.jsonl": "latest"}}

			if err := reconcileStoppedLeftover(sessions, "abc", mgr); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(mgr.calls, ","); got != "delete" {
				t.Errorf("calls = %s, want delete only", got)
			}
			assertSavedCopy(t, filepath.Join(sessions, "abc", ".claude"), "old")
		})
	}
}

func TestPhaseReconcileExisting_ResumeSkipsLeftoverNoSessionNames(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "sessions-claude")
	// Resumed onto another slot (--slot): no metadata names coi-leftover-1.
	writeLeftoverSession(t, sessions, "abc", "coi-leftover-2", "2026-11-22T10:00:00Z", "old")
	mgr := &stoppedLeftoverFake{files: map[string]string{"history.jsonl": "latest"}}

	if err := reconcileStoppedLeftover(sessions, "abc", mgr); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(mgr.calls, ","); got != "delete" {
		t.Errorf("calls = %s, want delete only", got)
	}
	assertSavedCopy(t, filepath.Join(sessions, "abc", ".claude"), "old")
}

func TestPhaseReconcileExisting_ResumeKeepsLeftoverWhenSaveFails(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "sessions-claude")
	writeLeftoverSession(t, sessions, "abc", "coi-leftover-1", "2026-11-22T10:00:00Z", "old")
	mgr := &stoppedLeftoverFake{pullErr: errors.New("permission denied")}

	err := reconcileStoppedLeftover(sessions, "abc", mgr)
	if err == nil || !strings.Contains(err.Error(), "leaving it in place") {
		t.Fatalf("err = %v, want a failed save that keeps the container", err)
	}
	if got := strings.Join(mgr.calls, ","); got != "pull" {
		t.Errorf("calls = %s, want pull and no delete", got)
	}
	assertSavedCopy(t, filepath.Join(sessions, "abc", ".claude"), "old")
}

func TestPhaseReconcileExisting_NewSessionDeletesStoppedLeftoverUnsaved(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "sessions-claude")
	writeLeftoverSession(t, sessions, "abc", "coi-leftover-1", "2026-11-22T10:00:00Z", "old")
	mgr := &stoppedLeftoverFake{files: map[string]string{"history.jsonl": "latest"}}

	if err := reconcileStoppedLeftover(sessions, "", mgr); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(mgr.calls, ","); got != "delete" {
		t.Errorf("calls = %s, want delete only", got)
	}
	assertSavedCopy(t, filepath.Join(sessions, "abc", ".claude"), "old")
}
