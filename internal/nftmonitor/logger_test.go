//go:build linux

package nftmonitor

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/logger"
)

// Regression tests for the issue #372 class: COI_NFT_DEBUG output (debugf) must
// go to the session log when a logger is set, not to os.Stderr — which during a
// `coi shell` is the user's attached terminal.

func TestDebugf_RoutesToSessionLoggerNotStderr(t *testing.T) {
	origDebug := Debug
	Debug = true
	defer func() { Debug = origDebug }()

	old := os.Stderr
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wp
	defer func() { os.Stderr = old }()

	tmp := t.TempDir()
	sl := logger.New("nftdbg", tmp)
	SetLogger(sl)
	defer SetLogger(nil)

	debugf("hello %d", 7)
	_ = sl.Close()

	_ = wp.Close()
	os.Stderr = old
	data, _ := io.ReadAll(rp)

	if len(data) != 0 {
		t.Errorf("[NFT-DEBUG] leaked to stderr with a session logger set: %q", data)
	}
	out, _ := os.ReadFile(filepath.Join(tmp, ".coi", "logs", "nftdbg.stdout.log"))
	if !strings.Contains(string(out), "[NFT-DEBUG] hello 7") {
		t.Errorf("debug output not routed to session log; got: %q", out)
	}
}

func TestDebugf_FallsBackToStderrWhenNoLogger(t *testing.T) {
	origDebug := Debug
	Debug = true
	defer func() { Debug = origDebug }()
	SetLogger(nil)

	old := os.Stderr
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wp
	defer func() { os.Stderr = old }()

	debugf("fallback %d", 9)

	_ = wp.Close()
	os.Stderr = old
	data, _ := io.ReadAll(rp)
	if !strings.Contains(string(data), "[NFT-DEBUG] fallback 9") {
		t.Errorf("expected stderr fallback when no logger is set; got: %q", data)
	}
}

func TestDebugf_SilentWhenDisabled(t *testing.T) {
	origDebug := Debug
	Debug = false
	defer func() { Debug = origDebug }()

	old := os.Stderr
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wp
	defer func() { os.Stderr = old }()

	tmp := t.TempDir()
	sl := logger.New("nftdbg-off", tmp)
	SetLogger(sl)
	defer SetLogger(nil)

	debugf("must not appear %d", 1)
	_ = sl.Close()

	_ = wp.Close()
	os.Stderr = old
	data, _ := io.ReadAll(rp)
	if len(data) != 0 {
		t.Errorf("debugf wrote to stderr while disabled: %q", data)
	}
	out, _ := os.ReadFile(filepath.Join(tmp, ".coi", "logs", "nftdbg-off.stdout.log"))
	if strings.Contains(string(out), "must not appear") {
		t.Errorf("debugf wrote to the log while disabled: %q", out)
	}
}
