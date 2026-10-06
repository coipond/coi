package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeStartIncus puts an `incus` on PATH whose `start` always fails, whose
// `list` reports the container RUNNING, and whose `exec ... true` exits with
// execRC. It returns the file the calls are logged to.
func fakeStartIncus(t *testing.T, execRC string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
  *" start c1"*) echo "Error: Failed to run: forklxc: exit status 1" >&2; exit 1 ;;
  *" list ^c1"*) echo "c1,RUNNING" ;;
  *" exec c1 -- true"*) exit ` + execRC + ` ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	timeout, interval := startSettleTimeout, startSettleInterval
	startSettleTimeout, startSettleInterval = 60*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { startSettleTimeout, startSettleInterval = timeout, interval })
	return logPath
}

func countCalls(t *testing.T, logPath, substr string) int {
	t.Helper()
	b, _ := os.ReadFile(logPath)
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// A start that aborts (here: every start fails) can still show RUNNING for a
// moment while the dying container's monitor answers state queries. That must
// not count as "came up anyway": the container can't run a command, so the
// start error is returned instead of a stopped container being handed on.
func TestStartWithIdmapRecovery_AbortedStartIsNotRunning(t *testing.T) {
	logPath := fakeStartIncus(t, "1")
	if err := startWithIdmapRecovery("c1"); err == nil {
		t.Fatal("an aborted start that only LOOKS running must return the start error")
	}
	if n := countCalls(t, logPath, " start c1"); n != 2 {
		t.Errorf("start attempts = %d, want 2 (first start + one unchanged retry)", n)
	}
}

func TestStartWithIsolationFallback_AbortedStartIsNotRunning(t *testing.T) {
	fakeStartIncus(t, "1")
	if err := StartWithIsolationFallback("c1"); err == nil {
		t.Fatal("an aborted start that only LOOKS running must return an error")
	}
}

// The soft forkstart error the poll exists for (start exits non-zero although
// the container is up) still counts as started, without a retry.
func TestStartWithIdmapRecovery_SoftForkstartErrorIsRunning(t *testing.T) {
	logPath := fakeStartIncus(t, "0")
	if err := startWithIdmapRecovery("c1"); err != nil {
		t.Fatalf("a container that is running and executes commands is up: %v", err)
	}
	if n := countCalls(t, logPath, " start c1"); n != 1 {
		t.Errorf("start attempts = %d, want 1", n)
	}
}
