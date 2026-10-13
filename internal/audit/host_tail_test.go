package audit

import (
	"bytes"
	"encoding/json"
	"os"
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
// and stamped; non-JSON noise is kept as an agent.stderr audit event.
func TestHostAuditTail_AgentEventsAndNoise(t *testing.T) {
	in := strings.NewReader(`{"ts":"2026-01-01T00:00:00Z","type":"exec","pid":7,"comm":"sh"}` + "\n" +
		"bash: some stderr noise\n" +
		`{"ts":"2026-01-01T00:00:01Z","type":"audit","msg":"m","raw":"type=EXECVE"}` + "\n")
	var out bytes.Buffer
	if err := copyHostAuditLines(in, "s1", "c1", &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 events, got %d:\n%s", len(lines), out.String())
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
	var noise Event
	if err := json.Unmarshal([]byte(lines[1]), &noise); err != nil {
		t.Fatal(err)
	}
	if noise.Type != TypeAudit || noise.Msg != "agent.stderr" || noise.Raw != "bash: some stderr noise" {
		t.Errorf("non-JSON line not kept as agent.stderr: %s", lines[1])
	}
}

// A monitor snapshot lists every process's command line, so a single record
// can exceed bufio.Scanner's token cap; it must still be printed rather than
// aborting the whole dump with "token too long".
func TestCopyHostAuditLines_OversizedRecord(t *testing.T) {
	big := `{"container":"c","pad":"` + strings.Repeat("x", 2*1024*1024) + `"}`
	in := strings.NewReader(big + "\n" + `{"id":"after"}` + "\n")
	var out bytes.Buffer
	if err := copyHostAuditLines(in, "", "", &out); err != nil {
		t.Fatalf("oversized record aborted the dump: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || lines[0] != big || lines[1] != `{"id":"after"}` {
		t.Errorf("want the oversized record and the next one, got %d lines", len(lines))
	}
}

// In --follow mode a record the monitor is mid-way through writing at EOF must
// be held until its newline arrives, not split into two halves and dropped.
func TestHostAuditCopier_PartialLineAcrossPolls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coi-test.jsonl")
	w, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var out bytes.Buffer
	c := newHostAuditCopier(r, "", "", &out)
	if _, err := w.WriteString(`{"id":"t-1","le`); err != nil {
		t.Fatal(err)
	}
	if err := c.drain(); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("partial line emitted early: %q", out.String())
	}
	if _, err := w.WriteString(`vel":"high"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := c.drain(); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != `{"id":"t-1","level":"high"}` {
		t.Errorf("record split across polls was not reassembled: %q", got)
	}
}

// A dump (no --follow) still prints a final record with no trailing newline.
func TestCopyHostAuditLines_FinalLineWithoutNewline(t *testing.T) {
	var out bytes.Buffer
	if err := copyHostAuditLines(strings.NewReader(`{"id":"last"}`), "", "", &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != `{"id":"last"}` {
		t.Errorf("final unterminated record dropped: %q", got)
	}
}
