package monitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Detector analyzes monitoring snapshots for security threats
type Detector struct {
	fileReadThresholdMB       float64
	fileReadRateMBPerSec      float64
	fileWriteThresholdMB      float64
	fileWriteRateMBPerSec     float64
	processCountThreshold     int
	processSpawnRateThreshold int
	previousProcessCount      int // -1 = first poll (no baseline yet)

	// reverseShellOneLinerLevel is the severity assigned to interpreter
	// one-liner reverse-shell matches (ReverseShellClassOneLiner: python -c,
	// perl -e, ruby -e, php -r). Configurable via #842's
	// [monitoring] reverse_shell_one_liners knob. The empty string means
	// "off" — do not emit these at all. Defaults to CRITICAL. The unambiguous
	// class (nc -e, /dev/tcp/, socat EXEC:, bash -i, ...) is always CRITICAL and
	// unaffected by this setting.
	reverseShellOneLinerLevel ThreatLevel
}

// NewDetector creates a new threat detector
func NewDetector(fileReadThresholdMB, fileReadRateMBPerSec float64) *Detector {
	return &Detector{
		fileReadThresholdMB:       fileReadThresholdMB,
		fileReadRateMBPerSec:      fileReadRateMBPerSec,
		fileWriteThresholdMB:      fileReadThresholdMB,  // Default: same as read threshold
		fileWriteRateMBPerSec:     fileReadRateMBPerSec, // Default: same as read rate threshold
		previousProcessCount:      -1,
		reverseShellOneLinerLevel: ThreatLevelCritical, // safe default: kill on critical
	}
}

// WithReverseShellOneLinerPolicy sets how interpreter one-liner reverse-shell
// matches (ReverseShellClassOneLiner) are treated (#842):
//   - "critical" (default): CRITICAL — auto-kill when auto_kill_on_critical is on.
//   - "warn":               WARNING  — logged and audited, never auto-kills/pauses.
//   - "off":                not reported at all.
//
// Unknown/empty values fall back to the safe default (critical). The unambiguous
// reverse-shell class is unaffected and always stays CRITICAL.
func (d *Detector) WithReverseShellOneLinerPolicy(policy string) *Detector {
	// Accept only the values the JSON schema enum allows ("critical", "warn",
	// "off") plus the empty string (field unset). Anything else falls through to
	// the safe default so a typo never silently weakens detection — and does not
	// diverge from `coi validate profile`, which would reject that same typo
	// (code-review #842).
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "warn":
		d.reverseShellOneLinerLevel = ThreatLevelWarning
	case "off":
		d.reverseShellOneLinerLevel = "" // do not emit
	default: // "critical", "", or anything unrecognized → safe default
		d.reverseShellOneLinerLevel = ThreatLevelCritical
	}
	return d
}

// WithProcessCountThreshold sets the process count threshold for fork-bomb detection.
func (d *Detector) WithProcessCountThreshold(threshold int) *Detector {
	d.processCountThreshold = threshold
	return d
}

// WithProcessSpawnRateThreshold sets the per-poll process-spawn-rate threshold.
// A delta exceeding this value between consecutive polls triggers a CRITICAL alert.
func (d *Detector) WithProcessSpawnRateThreshold(threshold int) *Detector {
	d.processSpawnRateThreshold = threshold
	return d
}

// Analyze examines a snapshot and returns detected threats
// newThreatEvent builds a ThreatEvent with the fields every detection shares —
// a fresh UUID, the snapshot timestamp, and the "pending" (not-yet-actioned)
// state — so each detection block only supplies what differs.
func newThreatEvent(ts time.Time, level ThreatLevel, category, title, description string, ev Evidence) ThreatEvent {
	return ThreatEvent{
		ID:          uuid.New().String(),
		Timestamp:   ts,
		Level:       level,
		Category:    category,
		Title:       title,
		Description: description,
		Evidence:    ev,
		Action:      "pending",
	}
}

// Analyze runs all detection checks against snapshot and returns the threats
// found, each with a severity level and supporting evidence.
func (d *Detector) Analyze(snapshot MonitorSnapshot) []ThreatEvent {
	var threats []ThreatEvent

	// 1. Detect reverse shells
	if snapshot.Processes.Available {
		reverseShells := DetectReverseShells(snapshot.Processes.Processes)
		for _, rs := range reverseShells {
			level := ThreatLevelCritical
			if rs.Class == ReverseShellClassOneLiner {
				// Apply the configurable one-liner policy (#842). Empty = "off":
				// skip emitting entirely.
				if d.reverseShellOneLinerLevel == "" {
					continue
				}
				level = d.reverseShellOneLinerLevel
			}
			threats = append(threats, newThreatEvent(snapshot.Timestamp, level, "process", "Reverse shell detected", fmt.Sprintf("Process '%s' (PID %d) matches reverse shell pattern '%s'",
				rs.Command, rs.PID, rs.Pattern), Evidence{Process: &rs}))
		}
	}

	// 2. Detect environment scanning
	if snapshot.Processes.Available {
		envScans := DetectEnvScanning(snapshot.Processes.Processes)
		for _, es := range envScans {
			threats = append(threats, newThreatEvent(snapshot.Timestamp, ThreatLevelWarning, "environment", "Environment variable scanning detected", fmt.Sprintf("Process '%s' (PID %d) is accessing environment variables",
				es.Command, es.PID), Evidence{Process: &es}))
		}
	}

	// 3. Detect unexpected network connections
	suspiciousConns := []Connection{}
	for _, conn := range snapshot.Network.Connections {
		if conn.Suspicious {
			suspiciousConns = append(suspiciousConns, conn)
		}
	}

	for _, conn := range suspiciousConns {
		level := ThreatLevelHigh
		// Elevate to critical if it's a known C2 port or metadata endpoint
		if extractPort(conn.RemoteAddr) == 4444 || extractPort(conn.RemoteAddr) == 5555 ||
			extractIP(conn.RemoteAddr) == "169.254.169.254" {
			level = ThreatLevelCritical
		}

		threats = append(threats, newThreatEvent(snapshot.Timestamp, level, "network", "Unexpected network connection", fmt.Sprintf("Connection to %s: %s",
			conn.RemoteAddr, conn.SuspectReason), Evidence{Network: &NetworkThreat{
			Connection: conn,
			Reason:     conn.SuspectReason,
			RemoteHost: extractIP(conn.RemoteAddr),
		}}))
	}

	// 4. Detect large workspace reads (possible data exfiltration)
	if snapshot.Filesystem.Available {
		fsExfil := DetectLargeReads(snapshot.Filesystem, d.fileReadThresholdMB, d.fileReadRateMBPerSec)
		if fsExfil != nil {
			threats = append(threats, newThreatEvent(snapshot.Timestamp, ThreatLevelHigh, "filesystem", "Large workspace read detected", fmt.Sprintf("Read %.2f MB at %.2f MB/sec (threshold: %.2f MB)",
				fsExfil.ReadBytesMB, fsExfil.ReadRate, fsExfil.Threshold), Evidence{Filesystem: fsExfil}))
		}

		// 4b. Detect large workspace writes (possible data exfiltration via tar, dd, etc.)
		fsWriteExfil := DetectLargeWrites(snapshot.Filesystem, d.fileWriteThresholdMB, d.fileWriteRateMBPerSec)
		if fsWriteExfil != nil {
			threats = append(threats, newThreatEvent(snapshot.Timestamp, ThreatLevelHigh, "filesystem", "Large workspace write detected", fmt.Sprintf("Write %.2f MB at %.2f MB/sec (threshold: %.2f MB)",
				fsWriteExfil.WriteBytesMB, fsWriteExfil.WriteRate, fsWriteExfil.Threshold), Evidence{FileWrite: fsWriteExfil}))
		}
	}

	// 5. Detect process count spike (fork bomb / runaway spawner)
	if snapshot.Processes.Available {
		if spike := DetectProcessCountSpike(snapshot.Processes, d.processCountThreshold); spike != nil {
			threats = append(threats, newThreatEvent(snapshot.Timestamp, ThreatLevelCritical, "process", "Process count spike detected", fmt.Sprintf("Container has %d processes (threshold: %d) — possible fork bomb or runaway spawner",
				spike.Count, spike.Threshold), Evidence{ProcessCount: spike}))
		}

		// 5b. Detect process spawn rate (delta-based fork-bomb detection)
		if rate := DetectProcessSpawnRate(snapshot.Processes.TotalCount, d.previousProcessCount, d.processSpawnRateThreshold); rate != nil {
			threats = append(threats, newThreatEvent(snapshot.Timestamp, ThreatLevelCritical, "process", "Process spawn rate spike detected", fmt.Sprintf("Container spawned %d new processes in one poll interval (threshold: %d)",
				rate.Delta, rate.Threshold), Evidence{ProcessCount: rate}))
		}
		d.previousProcessCount = snapshot.Processes.TotalCount
	} else {
		// Reset baseline so the next successful poll is treated as the first,
		// preventing a false spawn-rate alert after a gap in process collection.
		d.previousProcessCount = -1
	}

	// 6. Detect low disk space (WARNING level)
	if snapshot.Filesystem.Available && snapshot.Filesystem.TmpTotalMB > 0 {
		// Warn if /tmp is >80% full
		if snapshot.Filesystem.TmpUsedPercent > 80 {
			threats = append(threats, newThreatEvent(snapshot.Timestamp, ThreatLevelWarning, "filesystem", "Low disk space on /tmp", fmt.Sprintf("/tmp is %.1f%% full (%.0fMB used of %.0fMB total). Consider increasing tmpfs_size in config.",
				snapshot.Filesystem.TmpUsedPercent,
				snapshot.Filesystem.TmpUsedMB,
				snapshot.Filesystem.TmpTotalMB), Evidence{DiskSpace: &DiskSpaceInfo{
				TmpUsedMB:      snapshot.Filesystem.TmpUsedMB,
				TmpTotalMB:     snapshot.Filesystem.TmpTotalMB,
				TmpUsedPercent: snapshot.Filesystem.TmpUsedPercent,
			}}))
		}
	}

	return threats
}
