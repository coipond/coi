package audit

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/monitor"
)

// `coi audit` (dump mode) reads the log the monitor writes. Its threat events
// and snapshots carry no `type` field, which ParseLine rejects, so they used
// to be dropped silently and the dump printed nothing.
func TestHostAuditTail_MonitorRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coi-test.jsonl")
	log, err := monitor.NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	threat := monitor.ThreatEvent{
		ID:        "threat-1",
		Timestamp: time.Now(),
		Level:     monitor.ThreatLevelCritical,
		Category:  "network",
		Title:     "Metadata endpoint access",
		Action:    "killed",
	}
	if err := log.WriteThreat(threat); err != nil {
		t.Fatal(err)
	}
	if err := log.WriteSnapshot(monitor.MonitorSnapshot{Timestamp: time.Now(), ContainerName: "coi-test"}); err != nil {
		t.Fatal(err)
	}
	log.Close()

	var out bytes.Buffer
	if err := HostAuditTail(path, false, "coi-test", "coi-test", &out); err != nil {
		t.Fatalf("HostAuditTail: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 records (threat + snapshot), got %d:\n%s", len(lines), out.String())
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, lines[0])
	}
	if got["id"] != "threat-1" || got["level"] != "critical" || got["action"] != "killed" {
		t.Errorf("threat event not passed through intact: %s", lines[0])
	}
}

// A recording made with `coi audit --follow` (agent schema) is still decoded
// and stamped; non-JSON noise is skipped.
func TestHostAuditTail_AgentEventsAndNoise(t *testing.T) {
	in := strings.NewReader(`{"ts":"2026-01-01T00:00:00Z","type":"exec","pid":7,"comm":"sh"}` + "\n" +
		"bash: some stderr noise\n" +
		`{"ts":"2026-01-01T00:00:01Z","type":"audit","msg":"m","raw":"type=EXECVE"}` + "\n")
	var out bytes.Buffer
	if err := copyHostAuditLines(in, "s1", "c1", &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 events, got %d:\n%s", len(lines), out.String())
	}
	for _, ln := range lines {
		var ev Event
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.SessionID != "s1" || ev.Container != "c1" {
			t.Errorf("agent event not stamped: %s", ln)
		}
	}
}
