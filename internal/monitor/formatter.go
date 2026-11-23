package monitor

import (
	"fmt"
	"strings"
	"time"
)

// FormatSnapshot formats a monitoring snapshot as human-readable text
func FormatSnapshot(snapshot MonitorSnapshot) string {
	var sb strings.Builder
	writeHeader(&sb, snapshot)
	writeThreats(&sb, snapshot)
	writeNetwork(&sb, snapshot)
	writeProcesses(&sb, snapshot)
	writeFilesystem(&sb, snapshot)
	writeResources(&sb, snapshot)
	writeErrors(&sb, snapshot)
	return sb.String()
}

// writeHeader appends its section of the monitor snapshot to sb.
func writeHeader(sb *strings.Builder, snapshot MonitorSnapshot) {
	// Header
	fmt.Fprintf(sb, "Container: %s", snapshot.ContainerName)
	if snapshot.ContainerIP != "" {
		fmt.Fprintf(sb, " (%s)", snapshot.ContainerIP)
	}
	sb.WriteString("\n")
	fmt.Fprintf(sb, "Timestamp: %s\n", snapshot.Timestamp.Format(time.RFC3339))
	sb.WriteString(strings.Repeat("━", 70) + "\n\n")
}

// writeThreats appends its section of the monitor snapshot to sb.
func writeThreats(sb *strings.Builder, snapshot MonitorSnapshot) {
	// Threats summary
	if len(snapshot.Threats) > 0 {
		criticalCount := 0
		highCount := 0
		warningCount := 0
		infoCount := 0

		for _, threat := range snapshot.Threats {
			switch threat.Level {
			case ThreatLevelCritical:
				criticalCount++
			case ThreatLevelHigh:
				highCount++
			case ThreatLevelWarning:
				warningCount++
			case ThreatLevelInfo:
				infoCount++
			}
		}

		sb.WriteString("⚠ THREATS DETECTED: ")
		parts := []string{}
		if criticalCount > 0 {
			parts = append(parts, fmt.Sprintf("%d critical", criticalCount))
		}
		if highCount > 0 {
			parts = append(parts, fmt.Sprintf("%d high", highCount))
		}
		if warningCount > 0 {
			parts = append(parts, fmt.Sprintf("%d warning", warningCount))
		}
		if infoCount > 0 {
			parts = append(parts, fmt.Sprintf("%d info", infoCount))
		}
		sb.WriteString(strings.Join(parts, ", "))
		sb.WriteString("\n\n")

		// Recent threats
		sb.WriteString("RECENT THREATS\n")
		for _, threat := range snapshot.Threats {
			levelStr := string(threat.Level)
			switch threat.Level {
			case ThreatLevelCritical:
				levelStr = "CRITICAL"
			case ThreatLevelHigh:
				levelStr = "HIGH    "
			case ThreatLevelWarning:
				levelStr = "WARNING "
			case ThreatLevelInfo:
				levelStr = "INFO    "
			}

			fmt.Fprintf(sb, "  [%s] %s  %s\n",
				threat.Timestamp.Format("15:04:05"),
				levelStr,
				threat.Title)
			fmt.Fprintf(sb, "                      %s\n", threat.Description)
			if threat.Action != "" && threat.Action != "logged" {
				fmt.Fprintf(sb, "                      → Action: %s\n", threat.Action)
			}
			sb.WriteString("\n")
		}
	}
}

// writeNetwork appends its section of the monitor snapshot to sb.
func writeNetwork(sb *strings.Builder, snapshot MonitorSnapshot) {
	// Network stats
	fmt.Fprintf(sb, "NETWORK (%d active connections", snapshot.Network.ActiveConnections)
	if snapshot.Network.SuspiciousCount > 0 {
		fmt.Fprintf(sb, ", %d suspicious", snapshot.Network.SuspiciousCount)
	}
	sb.WriteString(")\n")

	if len(snapshot.Network.Connections) > 0 {
		sb.WriteString("  Protocol  Local Address       Remote Address       State        Status\n")
		for _, conn := range snapshot.Network.Connections {
			status := "✓ Normal"
			if conn.Suspicious {
				status = "⚠ SUSPICIOUS"
			}
			fmt.Fprintf(sb, "  %-8s  %-18s  %-18s  %-11s  %s\n",
				conn.Protocol, conn.LocalAddr, conn.RemoteAddr, conn.State, status)
		}
	} else {
		sb.WriteString("  No active connections\n")
	}
	sb.WriteString("\n")
}

// writeProcesses appends its section of the monitor snapshot to sb.
func writeProcesses(sb *strings.Builder, snapshot MonitorSnapshot) {
	// Process stats
	if snapshot.Processes.Available {
		fmt.Fprintf(sb, "PROCESSES (%d running)\n", snapshot.Processes.TotalCount)
		if len(snapshot.Processes.Processes) > 0 {
			sb.WriteString("  PID    User   Command                                  Flags\n")
			for _, proc := range snapshot.Processes.Processes {
				flags := ""
				if proc.EnvAccess {
					flags = "⚠ ENV SCAN"
				}

				// Truncate long commands
				cmd := proc.Command
				if len(cmd) > 40 {
					cmd = cmd[:37] + "..."
				}

				fmt.Fprintf(sb, "  %-6d %-6s %-40s %s\n",
					proc.PID, proc.User, cmd, flags)
			}
		}
	} else {
		sb.WriteString("PROCESSES\n  Not available\n")
	}
	sb.WriteString("\n")
}

// writeFilesystem appends its section of the monitor snapshot to sb.
func writeFilesystem(sb *strings.Builder, snapshot MonitorSnapshot) {
	// Filesystem stats
	if snapshot.Filesystem.Available {
		sb.WriteString("FILESYSTEM\n")
		reads := "Container I/O Reads:"
		if snapshot.Filesystem.WorkspaceDevice != "" {
			reads = "Workspace Reads:"
		}
		fmt.Fprintf(sb, "  %-20s %.2f MB (%.2f MB/sec)\n",
			reads, snapshot.Filesystem.TotalReadMB, snapshot.Filesystem.ReadRateMBPerSec)
		if snapshot.Filesystem.FilesAccessed > 0 {
			fmt.Fprintf(sb, "  %-20s %d\n", "Files Accessed:", snapshot.Filesystem.FilesAccessed)
		}
	} else {
		sb.WriteString("FILESYSTEM\n  Not available\n")
	}
	sb.WriteString("\n")
}

// writeResources appends its section of the monitor snapshot to sb.
func writeResources(sb *strings.Builder, snapshot MonitorSnapshot) {
	// Resource stats
	sb.WriteString("RESOURCES\n")
	fmt.Fprintf(sb, "  CPU:     %.1fs total (%.1fs user, %.1fs system)\n",
		snapshot.Resources.CPUTimeSeconds, snapshot.Resources.UserCPUSeconds, snapshot.Resources.SysCPUSeconds)
	if snapshot.Resources.MemoryLimitMB > 0 {
		memPercent := (snapshot.Resources.MemoryMB / snapshot.Resources.MemoryLimitMB) * 100
		fmt.Fprintf(sb, "  Memory:  %.0f MB / %.0f MB (%.1f%%)\n",
			snapshot.Resources.MemoryMB, snapshot.Resources.MemoryLimitMB, memPercent)
	} else {
		fmt.Fprintf(sb, "  Memory:  %.0f MB\n", snapshot.Resources.MemoryMB)
	}
	fmt.Fprintf(sb, "  I/O:     %.0f MB read, %.0f MB write\n",
		snapshot.Resources.IOReadMB, snapshot.Resources.IOWriteMB)
}

// writeErrors appends its section of the monitor snapshot to sb.
func writeErrors(sb *strings.Builder, snapshot MonitorSnapshot) {
	// Errors
	if len(snapshot.Errors) > 0 {
		sb.WriteString("\nERRORS\n")
		for _, err := range snapshot.Errors {
			fmt.Fprintf(sb, "  - %s\n", err)
		}
	}
}
