package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/tool"
)

// cleanupStoppedSession runs an ephemeral session's Cleanup on a stopped
// container whose user.coi.persistent key is key, saving a codex session.
// It returns the logged incus calls, Cleanup's log lines, the network
// teardown count and the saved metadata.
func cleanupStoppedSession(t *testing.T, key string) (calls, logs string, teardowns int, md *SessionMetadata) {
	t.Helper()
	name := "coi-persisted-cleanup-1"
	logPath := fakeLimitsIncusStatus(t, name, "", "STOPPED")
	dir := filepath.Dir(logPath)
	for path, content := range map[string]string{
		filepath.Join(dir, "keys", PersistentConfigKey):     key,
		filepath.Join(dir, "home", ".codex", "config.toml"): "x",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sessionsDir := t.TempDir()
	fake := &fakeNetworkManager{}
	var lines []string
	err := Cleanup(CleanupOptions{
		ContainerName:  name,
		SessionID:      "s1",
		Persistent:     false,
		SaveSession:    true,
		SessionsDir:    sessionsDir,
		Tool:           tool.NewCodex(),
		NetworkManager: fake,
		Logger:         func(msg string) { lines = append(lines, msg) },
	})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	b, _ := os.ReadFile(logPath)
	md, err = LoadSessionMetadata(filepath.Join(sessionsDir, "s1", "metadata.json"))
	if err != nil {
		t.Fatalf("no saved metadata: %v\nlog:\n%s", err, strings.Join(lines, "\n"))
	}
	return string(b), strings.Join(lines, "\n"), fake.teardownCalls, md
}

// `coi persist` on a running ephemeral session sets the key; the session's
// own cleanup after a poweroff must keep the container and save the
// metadata as persistent, so --resume inherits it.
func TestCleanup_KeepsContainerConvertedByPersist(t *testing.T) {
	calls, logs, teardowns, md := cleanupStoppedSession(t, "true")
	if strings.Contains(calls, "delete ") {
		t.Errorf("container deleted after coi persist; calls:\n%s", calls)
	}
	if teardowns != 0 {
		t.Errorf("network torn down %d times for a kept container", teardowns)
	}
	if !strings.Contains(logs, "Container kept (stopped)") {
		t.Errorf("want the kept (stopped) message; log:\n%s", logs)
	}
	if !md.Persistent {
		t.Error("saved metadata persistent = false; want true")
	}
}

// Without the key the stopped ephemeral container is still removed.
func TestCleanup_RemovesStoppedEphemeralContainer(t *testing.T) {
	calls, _, teardowns, md := cleanupStoppedSession(t, "false")
	if !strings.Contains(calls, "delete ") {
		t.Errorf("stopped ephemeral container not deleted; calls:\n%s", calls)
	}
	if teardowns != 1 {
		t.Errorf("network torn down %d times; want 1", teardowns)
	}
	if md.Persistent {
		t.Error("saved metadata persistent = true; want false")
	}
}
