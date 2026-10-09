package monitor

import (
	"fmt"
	"time"
)

// ThreatLevel indicates severity of detected threat
type ThreatLevel string

// Threat levels, in increasing order of severity.
const (
	ThreatLevelInfo     ThreatLevel = "info"
	ThreatLevelWarning  ThreatLevel = "warning"
	ThreatLevelHigh     ThreatLevel = "high"     // Auto-pause
	ThreatLevelCritical ThreatLevel = "critical" // Auto-kill
)

// ThreatEvent represents a detected security event
type ThreatEvent struct {
	ID          string      `json:"id"` // Unique event ID
	Timestamp   time.Time   `json:"timestamp"`
	Level       ThreatLevel `json:"level"`
	Category    string      `json:"category"`    // "network", "process", "filesystem", "env"
	Title       string      `json:"title"`       // "Reverse shell detected"
	Description string      `json:"description"` // Detailed explanation
	Evidence    Evidence    `json:"evidence"`    // Supporting data (typed union)
	Action      string      `json:"action"`      // "logged", "alerted", "paused", "killed"
}

// NetworkThreat represents suspicious network activity
type NetworkThreat struct {
	Connection Connection `json:"connection"`
	Reason     string     `json:"reason"`      // "Unexpected IP", "Reverse shell port", etc.
	RemoteHost string     `json:"remote_host"` // Resolved hostname if available
}

// ProcessThreat represents suspicious process activity
type ProcessThreat struct {
	PID        int      `json:"pid"`
	Command    string   `json:"command"` // Full command line
	User       string   `json:"user"`
	Pattern    string   `json:"pattern"`         // "nc -e", "bash -i", etc.
	Indicators []string `json:"indicators"`      // List of suspicious patterns matched
	Class      string   `json:"class,omitempty"` // Reverse-shell pattern class (see ReverseShellClass*); "" = strong/unambiguous
}

// FilesystemThreat represents suspicious file access
type FilesystemThreat struct {
	ReadBytesMB float64 `json:"read_bytes_mb"`
	ReadRate    float64 `json:"read_rate_mb_per_sec"`
	FilesRead   int     `json:"files_read"`
	Duration    string  `json:"duration"`
	Threshold   float64 `json:"threshold_mb"`
}

// DiskSpaceInfo holds disk space metrics for /tmp threshold warnings
type DiskSpaceInfo struct {
	TmpUsedMB      float64 `json:"tmp_used_mb"`
	TmpTotalMB     float64 `json:"tmp_total_mb"`
	TmpUsedPercent float64 `json:"tmp_used_percent"`
}

// ProcessCountThreat represents a process-count spike (fork bomb or runaway spawner)
type ProcessCountThreat struct {
	Count     int `json:"count"`           // Observed process count
	Threshold int `json:"threshold"`       // Configured limit
	Delta     int `json:"delta,omitempty"` // Processes spawned since last poll (spawn-rate check only)
}

// SensitiveFileThreat records an access to a sensitive file monitored via fanotify.
type SensitiveFileThreat struct {
	Path   string `json:"path"`   // container-relative path, e.g. "etc/shadow"
	Access string `json:"access"` // "read" or "write"
	Pid    int    `json:"pid"`    // host PID of the accessing process
}

// AuthLogThreat records a security-relevant line from auth.log or syslog.
type AuthLogThreat struct {
	LogFile string `json:"log_file"` // "auth.log" or "syslog"
	Line    string `json:"line"`     // matched log line (truncated at 300 chars)
	Pattern string `json:"pattern"`  // name of matched pattern
}

// ProcEventThreat records a suspicious process execution or privilege
// escalation detected via the PROC_EVENTS netlink interface.
type ProcEventThreat struct {
	PID     int    `json:"pid"`
	Command string `json:"command"` // cmdline (truncated at 300 chars)
	Pattern string `json:"pattern"` // matched pattern name, e.g. "bash-interactive"
}

// Evidence holds threat-specific supporting data.
// Exactly one field will be non-nil per threat event.
type Evidence struct {
	Process       *ProcessThreat         `json:"process,omitempty"`
	Network       *NetworkThreat         `json:"network,omitempty"`
	Filesystem    *FilesystemThreat      `json:"filesystem,omitempty"`
	FileWrite     *FilesystemWriteThreat `json:"file_write,omitempty"`
	DiskSpace     *DiskSpaceInfo         `json:"disk_space,omitempty"`
	ProcessCount  *ProcessCountThreat    `json:"process_count,omitempty"`
	AuthLog       *AuthLogThreat         `json:"auth_log,omitempty"`
	ProcEvent     *ProcEventThreat       `json:"proc_event,omitempty"`
	SensitiveFile *SensitiveFileThreat   `json:"sensitive_file,omitempty"`
}

// String returns a summary of the evidence for deduplication keys
func (e Evidence) String() string {
	switch {
	case e.Process != nil:
		return fmt.Sprintf("pid:%d cmd:%s", e.Process.PID, e.Process.Command)
	case e.Network != nil:
		return fmt.Sprintf("remote:%s reason:%s", e.Network.Connection.RemoteAddr, e.Network.Reason)
	case e.Filesystem != nil:
		return fmt.Sprintf("read:%.2fMB", e.Filesystem.ReadBytesMB)
	case e.FileWrite != nil:
		return fmt.Sprintf("write:%.2fMB", e.FileWrite.WriteBytesMB)
	case e.DiskSpace != nil:
		return fmt.Sprintf("tmp:%.1f%%", e.DiskSpace.TmpUsedPercent)
	case e.ProcessCount != nil:
		if e.ProcessCount.Delta > 0 {
			return fmt.Sprintf("spawn-delta:%d", e.ProcessCount.Delta)
		}
		return fmt.Sprintf("procs:%d", e.ProcessCount.Count)
	case e.AuthLog != nil:
		return fmt.Sprintf("auth:%s:%s", e.AuthLog.LogFile, e.AuthLog.Pattern)
	case e.ProcEvent != nil:
		return fmt.Sprintf("proc:%d:%s", e.ProcEvent.PID, e.ProcEvent.Pattern)
	case e.SensitiveFile != nil:
		return fmt.Sprintf("file:%s:%s", e.SensitiveFile.Path, e.SensitiveFile.Access)
	default:
		return ""
	}
}

// MonitorSnapshot represents a point-in-time view of container metrics
type MonitorSnapshot struct {
	Timestamp     time.Time       `json:"timestamp"`
	ContainerName string          `json:"container"`
	ContainerIP   string          `json:"container_ip,omitempty"`
	Network       NetworkStats    `json:"network"`
	Processes     ProcessStats    `json:"processes"`
	Filesystem    FilesystemStats `json:"filesystem"`
	Resources     ResourceStats   `json:"resources"`
	Threats       []ThreatEvent   `json:"threats"`
	Errors        []string        `json:"errors,omitempty"`
}

// ProcessStats holds process information
type ProcessStats struct {
	Available  bool      `json:"available"`
	TotalCount int       `json:"total_count"`
	Processes  []Process `json:"processes,omitempty"`
}

// Process represents a running process
type Process struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	User      string `json:"user"`
	Command   string `json:"command"`        // Full command line
	Name      string `json:"name,omitempty"` // Kernel process name (/proc/<pid>/status Name, i.e. comm): set from the executable, unaffected by argv[0]
	EnvAccess bool   `json:"env_access"`     // Has accessed /proc/*/environ
}

// FilesystemStats holds workspace access statistics
type FilesystemStats struct {
	Available         bool    `json:"available"`
	WorkspacePath     string  `json:"workspace_path,omitempty"`
	TotalReadMB       float64 `json:"total_read_mb"`
	ReadRateMBPerSec  float64 `json:"read_rate_mb_per_sec"`
	TotalWriteMB      float64 `json:"total_write_mb"`
	WriteRateMBPerSec float64 `json:"write_rate_mb_per_sec"`
	FilesAccessed     int     `json:"files_accessed,omitempty"`
	// Disk space monitoring (for /tmp and /workspace)
	TmpUsedMB      float64 `json:"tmp_used_mb,omitempty"`
	TmpTotalMB     float64 `json:"tmp_total_mb,omitempty"`
	TmpUsedPercent float64 `json:"tmp_used_percent,omitempty"`
}

// NetworkStats represents network connection information
type NetworkStats struct {
	ActiveConnections int          `json:"active_connections"`
	Connections       []Connection `json:"connections,omitempty"`
	SuspiciousCount   int          `json:"suspicious_count"`
}

// Connection represents a network connection
type Connection struct {
	Protocol      string `json:"protocol"`
	LocalAddr     string `json:"local_addr"`
	RemoteAddr    string `json:"remote_addr"`
	State         string `json:"state"`
	UID           int    `json:"uid,omitempty"`
	Suspicious    bool   `json:"suspicious"`               // Flagged as suspicious
	SuspectReason string `json:"suspect_reason,omitempty"` // Why flagged
}

// ResourceStats represents container resource usage
type ResourceStats struct {
	CPUTimeSeconds float64 `json:"cpu_time_seconds"`
	UserCPUSeconds float64 `json:"user_cpu_seconds"`
	SysCPUSeconds  float64 `json:"sys_cpu_seconds"`
	MemoryMB       float64 `json:"memory_mb"`
	MemoryLimitMB  float64 `json:"memory_limit_mb,omitempty"`
	IOReadMB       float64 `json:"io_read_mb"`
	IOWriteMB      float64 `json:"io_write_mb"`
}

// DaemonConfig configures the monitoring daemon
type DaemonConfig struct {
	ContainerName  string
	WorkspacePath  string
	PollInterval   time.Duration
	AuditLogPath   string
	AllowedCIDRs   []string // CIDR ranges for allowed networks (static snapshot / fallback)
	AllowedDomains []string // Domains from network allowlist

	// AllowedCIDRsProvider, when set, is consulted on every collection for the
	// CURRENT allowlist (e.g. the live nft set in allowlist mode) so the monitor
	// stays in lockstep with the firewall rather than drifting from a frozen
	// snapshot. Falls back to AllowedCIDRs when it returns nothing.
	AllowedCIDRsProvider func() []string
	// PermittedDestination, when set, reports whether the container's firewall
	// deliberately accepts TCP/UDP traffic to ip:port (e.g. a [[network.hosts]] LAN
	// service, including one added at runtime). Such connections are not flagged
	// as private-network or allowlist violations; other checks still apply.
	PermittedDestination PermittedDestinationFunc

	// Detection database directories (populated from config.Detection)
	GTFOBinsDir string // Local GTFOBins clone directory
	SigmaDir    string // Local Sigma clone directory

	// Threat detection thresholds
	FileReadThresholdMB   float64 // MB read in poll interval
	FileReadRateMBPerSec  float64 // MB/sec sustained rate
	FileWriteThresholdMB  float64 // MB written in poll interval
	FileWriteRateMBPerSec float64 // MB/sec sustained write rate
	ProcessCountThreshold int     // Max processes before fork-bomb alert (0 = disabled)

	// Threat detection thresholds (continued)
	ProcessSpawnRateThreshold int // Max processes spawned per poll interval before alert (0 = disabled)

	// Reverse-shell one-liner policy (#842): "critical" (default), "warn", or
	// "off". Controls the severity of interpreter one-liner reverse-shell
	// matches (python -c, perl -e, ...). Empty string = default (critical).
	ReverseShellOneLinerPolicy string

	// Response configuration
	AutoPauseOnHigh    bool
	AutoKillOnCritical bool
	ForensicsOnKill    bool // preserve a forensic copy of the container before an auto-kill deletes it

	// Callbacks
	OnThreat func(ThreatEvent)
	OnError  func(error)
	OnAction func(action, message string) // Called when container is paused/killed
}

// PermittedDestinationFunc reports whether the firewall accepts TCP/UDP traffic
// from the container to ip:port.
type PermittedDestinationFunc func(ip string, port int) bool
