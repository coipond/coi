package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/tool"
)

// cleanupFailedSave runs Cleanup on a stopped non-persistent container whose
// session save fails (the sessions dir is a file, so it can't be created) and
// returns the cleanup messages, the logged incus calls and the network fake.
func cleanupFailedSave(t *testing.T, name string, keep bool) (string, string, *fakeNetworkManager) {
	t.Helper()
	logPath := fakeLimitsIncusStatus(t, name, "", "STOPPED")
	sessionsDir := filepath.Join(t.TempDir(), "sessions-codex")
	if err := os.WriteFile(sessionsDir, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeNetworkManager{}
	var logs []string
	err := Cleanup(CleanupOptions{
		ContainerName:    name,
		SessionID:        "s1",
		SaveSession:      true,
		SessionsDir:      sessionsDir,
		Tool:             tool.NewCodex(),
		NetworkManager:   fake,
		KeepOnFailedSave: keep,
		Logger:           func(msg string) { logs = append(logs, msg) },
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	calls, _ := os.ReadFile(logPath)
	return strings.Join(logs, "\n"), string(calls), fake
}

func TestCleanup_FailedSaveDeletesAndSaysWhatWasLost(t *testing.T) {
	out, calls, fake := cleanupFailedSave(t, "coi-failed-save-test-0", false)
	if !strings.Contains(calls, "delete") {
		t.Errorf("container was not deleted; incus calls:\n%s", calls)
	}
	if fake.teardownCalls != 1 {
		t.Errorf("Teardown ran %d times, want 1", fake.teardownCalls)
	}
	for _, want := range []string{
		"Container removed - session data could NOT be saved (failed to create session directory:",
		"the conversation since the last saved copy is lost",
		"keep_on_failed_save = true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestCleanup_FailedSaveKeepsContainerWhenConfigured(t *testing.T) {
	out, calls, fake := cleanupFailedSave(t, "coi-failed-save-test-1", true)
	if strings.Contains(calls, "delete") || strings.Contains(calls, "stop") {
		t.Errorf("container was stopped or deleted; incus calls:\n%s", calls)
	}
	if fake.teardownCalls != 1 {
		t.Errorf("Teardown ran %d times, want 1", fake.teardownCalls)
	}
	if strings.Contains(out, "removed") {
		t.Errorf("claimed the container was removed:\n%s", out)
	}
	for _, want := range []string{
		"Container kept (stopped) - session data could NOT be saved (failed to create session directory:",
		"'coi shell --resume'",
		"'coi kill coi-failed-save-test-1'",
		"'coi clean'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// The setting only applies to a failed save: a saved session's stopped
// container is still removed.
func TestCleanup_KeepOnFailedSaveDeletesAfterSuccessfulSave(t *testing.T) {
	name := "coi-failed-save-test-2"
	logPath := fakeLimitsIncusStatus(t, name, "", "STOPPED")
	var logs []string
	err := Cleanup(CleanupOptions{
		ContainerName:    name,
		Tool:             tool.NewCodex(),
		KeepOnFailedSave: true,
		Logger:           func(msg string) { logs = append(logs, msg) },
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	calls, _ := os.ReadFile(logPath)
	if !strings.Contains(string(calls), "delete") {
		t.Errorf("container was not deleted; incus calls:\n%s\nlogs:\n%s", calls, strings.Join(logs, "\n"))
	}
}
