package monitor

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestSensitiveFilesTable verifies the sensitiveFiles table is self-consistent:
// every entry has a non-empty rel path, at least one level set, and the correct
// category for its type.
func TestSensitiveFilesTable(t *testing.T) {
	for _, sf := range sensitiveFiles {
		if sf.rel == "" {
			t.Errorf("sensitiveFile with empty rel path")
		}
		if sf.openLevel == "" && sf.writeLevel == "" {
			t.Errorf("sensitiveFile %q has neither openLevel nor writeLevel set", sf.rel)
		}
		if sf.openLevel != "" && sf.openTitle == "" {
			t.Errorf("sensitiveFile %q has openLevel but no openTitle", sf.rel)
		}
		if sf.writeLevel != "" && sf.writeTitle == "" {
			t.Errorf("sensitiveFile %q has writeLevel but no writeTitle", sf.rel)
		}
		if sf.category == "" {
			t.Errorf("sensitiveFile %q has no category", sf.rel)
		}
	}
}

// TestSensitiveFilesThreatLevels checks specific files have the expected levels.
func TestSensitiveFilesThreatLevels(t *testing.T) {
	fileMap := make(map[string]*monitoredFile)
	for i := range sensitiveFiles {
		fileMap[sensitiveFiles[i].rel] = &sensitiveFiles[i]
	}

	cases := []struct {
		rel        string
		openLevel  ThreatLevel
		writeLevel ThreatLevel
	}{
		{"etc/shadow", ThreatLevelHigh, ThreatLevelCritical},
		{"etc/sudoers", "", ThreatLevelCritical},
		{"root/.ssh/authorized_keys", "", ThreatLevelCritical},
		{"etc/passwd", "", ThreatLevelHigh},
		{"etc/gshadow", ThreatLevelHigh, ThreatLevelHigh},
	}

	for _, tc := range cases {
		sf, ok := fileMap[tc.rel]
		if !ok {
			t.Errorf("expected %q in sensitiveFiles, not found", tc.rel)
			continue
		}
		if sf.openLevel != tc.openLevel {
			t.Errorf("%q openLevel: got %q, want %q", tc.rel, sf.openLevel, tc.openLevel)
		}
		if sf.writeLevel != tc.writeLevel {
			t.Errorf("%q writeLevel: got %q, want %q", tc.rel, sf.writeLevel, tc.writeLevel)
		}
	}
}

// TestMarkMaskOnlyFdEvents checks every mark mask holds only events that
// carry an fd: fanotify_mark refuses any other event with EINVAL in a group
// without FAN_REPORT_FID, so the file would never be watched.
func TestMarkMaskOnlyFdEvents(t *testing.T) {
	for i := range sensitiveFiles {
		sf := &sensitiveFiles[i]
		mask := sf.markMask()
		if extra := mask &^ (unix.FAN_OPEN | unix.FAN_CLOSE_WRITE); extra != 0 {
			t.Errorf("%q mark mask has events without an fd: %#x", sf.rel, extra)
		}
		if sf.openLevel != "" && mask&unix.FAN_OPEN == 0 {
			t.Errorf("%q has openLevel but no FAN_OPEN", sf.rel)
		}
		if sf.writeLevel != "" && mask&unix.FAN_CLOSE_WRITE == 0 {
			t.Errorf("%q has writeLevel but no FAN_CLOSE_WRITE", sf.rel)
		}
	}
}

// TestSensitiveFileThreatEvidence verifies that Evidence.String() formats the
// SensitiveFile evidence correctly for deduplication.
func TestSensitiveFileThreatEvidence(t *testing.T) {
	ev := Evidence{
		SensitiveFile: &SensitiveFileThreat{
			Path:   "etc/shadow",
			Access: "read",
			Pid:    12345,
		},
	}
	got := ev.String()
	want := "file:etc/shadow:read"
	if got != want {
		t.Errorf("Evidence.String() = %q, want %q", got, want)
	}
}

// TestSensitiveFileThreatEvidenceWrite verifies write access formats correctly.
func TestSensitiveFileThreatEvidenceWrite(t *testing.T) {
	ev := Evidence{
		SensitiveFile: &SensitiveFileThreat{
			Path:   "etc/sudoers",
			Access: "write",
			Pid:    99,
		},
	}
	got := ev.String()
	want := "file:etc/sudoers:write"
	if got != want {
		t.Errorf("Evidence.String() = %q, want %q", got, want)
	}
}

// TestFileWatcherFireEmitsThreatEvent verifies that FileWatcher.fire() constructs
// a properly-formed ThreatEvent and delivers it via onThreat.
func TestFileWatcherFireEmitsThreatEvent(t *testing.T) {
	var got ThreatEvent
	w := NewFileWatcher("test-container", func(e ThreatEvent) { got = e }, nil)

	w.fire(ThreatLevelHigh, "credential_access",
		"Shadow read", "A process opened /etc/shadow",
		"etc/shadow", "read", 42)

	if got.Level != ThreatLevelHigh {
		t.Errorf("level: got %q, want %q", got.Level, ThreatLevelHigh)
	}
	if got.Category != "credential_access" {
		t.Errorf("category: got %q", got.Category)
	}
	if got.Title != "Shadow read" {
		t.Errorf("title: got %q", got.Title)
	}
	if got.Evidence.SensitiveFile == nil {
		t.Fatal("Evidence.SensitiveFile is nil")
	}
	sf := got.Evidence.SensitiveFile
	if sf.Path != "etc/shadow" {
		t.Errorf("path: got %q", sf.Path)
	}
	if sf.Access != "read" {
		t.Errorf("access: got %q", sf.Access)
	}
	if sf.Pid != 42 {
		t.Errorf("pid: got %d", sf.Pid)
	}
	if got.ID == "" {
		t.Error("ID should not be empty")
	}
	if got.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

// TestFileWatcherFireNilCallback verifies fire() is a no-op when onThreat is nil.
func TestFileWatcherFireNilCallback(t *testing.T) {
	w := NewFileWatcher("test-container", nil, nil)
	// Must not panic.
	w.fire(ThreatLevelHigh, "credential_access", "title", "desc", "etc/shadow", "read", 1)
}
