package session

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/tool"
)

// fakeNetworkManager records Teardown/SetupForContainer calls so tests can
// assert the session-cleanup orchestration without touching real nft state.
type fakeNetworkManager struct {
	teardownCalls int
	teardownName  string
	setupCalls    int
}

func (f *fakeNetworkManager) SetupForContainer(_ context.Context, name string) error {
	f.setupCalls++
	return nil
}

func (f *fakeNetworkManager) Teardown(_ context.Context, name string) error {
	f.teardownCalls++
	f.teardownName = name
	return nil
}

// Regression test for the intermittent auto-kill nft-rule-cleanup flake: when
// the container has already been removed (e.g. the threat responder auto-killed
// it — the responder stops+deletes the container itself), Cleanup must STILL run
// NetworkManager.Teardown as a backstop, so the per-IP nft rules are not
// orphaned. Previously the "already removed" branch only logged.
//
// The fake incus lists no container, so mgr.Exists() returns false.
func TestCleanup_TeardownRunsWhenContainerAlreadyRemoved(t *testing.T) {
	fakeLimitsIncus(t, "coi-nonexistent-backstop-test-0", "")
	fake := &fakeNetworkManager{}
	err := Cleanup(CleanupOptions{
		ContainerName:  "coi-nonexistent-backstop-test-0",
		Persistent:     false,
		NetworkManager: fake,
		Logger:         func(string) {},
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if fake.teardownCalls != 1 {
		t.Fatalf("expected Teardown to run exactly once on the already-removed path, got %d", fake.teardownCalls)
	}
	if fake.teardownName != "coi-nonexistent-backstop-test-0" {
		t.Errorf("Teardown called with wrong container name: %q", fake.teardownName)
	}
}

// In persistent mode the container is intentionally kept, so the backstop must
// NOT run (no network teardown), even when the container is already gone.
func TestCleanup_NoTeardownBackstopInPersistentMode(t *testing.T) {
	fakeLimitsIncus(t, "coi-nonexistent-backstop-test-1", "")
	fake := &fakeNetworkManager{}
	err := Cleanup(CleanupOptions{
		ContainerName:  "coi-nonexistent-backstop-test-1",
		Persistent:     true,
		NetworkManager: fake,
		Logger:         func(string) {},
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if fake.teardownCalls != 0 {
		t.Errorf("expected no Teardown backstop in persistent mode, got %d calls", fake.teardownCalls)
	}
}

// fakeUnreachableIncus puts an `incus` on PATH that fails every call, as when
// the daemon is down. It returns the file the calls are logged to.
func fakeUnreachableIncus(t *testing.T) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
echo "Error: Failed to connect to local daemon" >&2
exit 1
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// When incus can't say whether the container exists, Cleanup must not treat
// it as gone: the container may still be there, so no network teardown, no
// stop or delete, no "already removed" claim, and the user is told the
// session was not saved.
func TestCleanup_IncusUnreachableLeavesContainerUntouched(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		logPath := fakeUnreachableIncus(t)
		fake := &fakeNetworkManager{}
		var logs []string
		err := Cleanup(CleanupOptions{
			ContainerName:  "coi-unreachable-test-0",
			Persistent:     persistent,
			SaveSession:    true,
			SessionID:      "s1",
			SessionsDir:    t.TempDir(),
			Tool:           tool.NewClaude(),
			NetworkManager: fake,
			Logger:         func(msg string) { logs = append(logs, msg) },
		})
		if err != nil {
			t.Fatalf("persistent=%v: Cleanup returned error: %v", persistent, err)
		}
		if fake.teardownCalls != 0 {
			t.Errorf("persistent=%v: Teardown ran %d times on an unreachable incus", persistent, fake.teardownCalls)
		}
		out := strings.Join(logs, "\n")
		if strings.Contains(out, "already removed") || strings.Contains(out, "no longer exists") {
			t.Errorf("persistent=%v: claimed the container is gone:\n%s", persistent, out)
		}
		if !strings.Contains(out, "incus unreachable") || !strings.Contains(out, "NOT saved") {
			t.Errorf("persistent=%v: missing the fail-safe message:\n%s", persistent, out)
		}
		calls, _ := os.ReadFile(logPath)
		for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
			if !strings.Contains(line, "list ") {
				t.Errorf("persistent=%v: unexpected incus call %q", persistent, line)
			}
		}
	}
}
