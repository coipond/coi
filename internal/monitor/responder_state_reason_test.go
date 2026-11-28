package monitor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePauseIncus puts an `incus` on PATH that logs its calls and exits with
// configSetExit for `config set` (0 for everything else).
func fakePauseIncus(t *testing.T, configSetExit string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\ncase \"$*\" in\n  *\"config set \"*) exit " + configSetExit + " ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func TestResponder_PauseRecordsMonitorReason(t *testing.T) {
	logPath := fakePauseIncus(t, "0")
	r := NewResponder("c1", true, false, nil, nil)

	if err := r.Handle(context.Background(), ThreatEvent{Level: ThreatLevelHigh, Category: "network", Title: "Reverse shell detected"}); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(logPath)
	calls := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(calls) != 2 || !strings.HasSuffix(calls[0], "pause c1") ||
		!strings.Contains(calls[1], "config set c1 user.coi.state_reason=monitor:Reverse shell detected user.coi.state_reason_at=") {
		t.Errorf("calls = %q, want pause then the monitor reason", calls)
	}
}

func TestResponder_PauseSurvivesFailedReasonWrite(t *testing.T) {
	fakePauseIncus(t, "1")
	r := NewResponder("c1", true, false, nil, nil)
	var errs []error
	r.SetOnError(func(e error) { errs = append(errs, e) })
	var actions []string
	r.SetOnAction(func(action, _ string) { actions = append(actions, action) })

	if err := r.Handle(context.Background(), ThreatEvent{Level: ThreatLevelHigh, Title: "x"}); err != nil {
		t.Fatalf("Handle = %v, want the pause to succeed", err)
	}
	if !r.paused || len(actions) != 1 || actions[0] != "paused" {
		t.Errorf("paused = %v, actions = %q; want paused", r.paused, actions)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "pause reason") {
		t.Errorf("errors = %v, want one reason-write error", errs)
	}
}
