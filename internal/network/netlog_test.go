package network

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/logger"
)

// Regression test for issue #372: network diagnostics (the background IP-refresh
// goroutine in particular) must go to the session log files, not stderr — which
// in a coi shell is the user's tmux terminal.
func TestNetworkLogging_RoutesToSessionLoggerNotStderr(t *testing.T) {
	// Capture the standard logger's output (its default sink is os.Stderr).
	var stdlog bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&stdlog)
	t.Cleanup(func() { log.SetOutput(orig) })

	// Default (no session logger): falls back to the standard logger.
	SetLogger(nil)
	logWarnf("fallback warning %d", 1)
	logInfof("fallback info %d", 2)
	if !strings.Contains(stdlog.String(), "fallback warning 1") {
		t.Errorf("expected fallback to standard logger, got: %q", stdlog.String())
	}

	// With a session logger set, output must go to the session files and NOT to
	// the standard logger / stderr.
	tmp := t.TempDir()
	sl := logger.New("netlog-test", tmp)
	SetLogger(sl)
	t.Cleanup(func() { SetLogger(nil) })

	stdlog.Reset()
	logInfof("routed info %d", 3)
	logWarnf("routed warning %d", 4)
	_ = sl.Close()

	if stdlog.Len() != 0 {
		t.Errorf("network output leaked to stderr/standard logger: %q", stdlog.String())
	}

	logsDir := filepath.Join(tmp, ".coi", "logs")
	out, _ := os.ReadFile(filepath.Join(logsDir, "netlog-test.stdout.log"))
	if !strings.Contains(string(out), "routed info 3") {
		t.Errorf("info message not routed to session stdout log; got: %q", string(out))
	}
	errf, _ := os.ReadFile(filepath.Join(logsDir, "netlog-test.stderr.log"))
	if !strings.Contains(string(errf), "routed warning 4") {
		t.Errorf("warning message not routed to session stderr log; got: %q", string(errf))
	}
}

// Regression test for the code-review findings on PR #512: coi run /
// ConfigureContainer construct a Manager with a discard logger to silence
// network output, but the resolver/nft helpers log via the package logger.
// NewManager must adopt its logger so that choice is honoured — a discard
// logger actually discards (not leak to stderr), and a file logger routes to
// the session files.
func TestNewManager_AdoptsLoggerForPackageDiagnostics(t *testing.T) {
	t.Run("discard logger silences package diagnostics", func(t *testing.T) {
		var stdlog bytes.Buffer
		orig := log.Writer()
		log.SetOutput(&stdlog)
		t.Cleanup(func() { log.SetOutput(orig); SetLogger(nil) })

		// Simulate coi run / ConfigureContainer: a discard logger passed to the
		// Manager. Before the fix the package logger stayed nil and these lines
		// fell through to the standard logger (stderr).
		_ = NewManager(nil, logger.NewDiscard())
		logInfof("resolver info should be discarded %d", 1)
		logWarnf("resolver warning should be discarded %d", 2)

		if stdlog.Len() != 0 {
			t.Errorf("network diagnostics leaked to stderr despite discard logger: %q", stdlog.String())
		}
	})

	t.Run("file logger routes package diagnostics to session files", func(t *testing.T) {
		var stdlog bytes.Buffer
		orig := log.Writer()
		log.SetOutput(&stdlog)
		t.Cleanup(func() { log.SetOutput(orig); SetLogger(nil) })

		tmp := t.TempDir()
		sl := logger.New("newmgr-test", tmp)
		_ = NewManager(nil, sl)
		logInfof("routed via manager %d", 7)
		_ = sl.Close()

		if stdlog.Len() != 0 {
			t.Errorf("network diagnostics leaked to stderr despite file logger: %q", stdlog.String())
		}
		out, _ := os.ReadFile(filepath.Join(tmp, ".coi", "logs", "newmgr-test.stdout.log"))
		if !strings.Contains(string(out), "routed via manager 7") {
			t.Errorf("manager-adopted logger did not route to session log; got: %q", string(out))
		}
	})
}
