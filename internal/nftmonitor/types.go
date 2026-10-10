package nftmonitor

import "time"

// NetworkEvent represents a network activity event captured from nftables logs
type NetworkEvent struct {
	Timestamp   time.Time
	ContainerIP string
	SrcIP       string
	DstIP       string
	DstPort     int
	SrcPort     int
	Protocol    string // "TCP", "UDP", "ICMP"
	Flags       string // "SYN", "ACK", etc.
	Interface   string // IN/OUT interfaces
}

// Config holds the configuration for the NFT monitoring daemon
type Config struct {
	ContainerName string
	ContainerIP   string
	AllowedCIDRs  []string
	// PermittedDestination, when set, reports whether the container's firewall
	// deliberately accepts proto ("tcp"/"udp") traffic to ip:port (e.g. a [[network.hosts]] LAN
	// service, including one added at runtime). Such connections are not flagged
	// as private-network, allowlist or DNS-server violations; other checks apply.
	PermittedDestination func(proto, ip string, port int) bool
	GatewayIP            string
	AuditLogPath         string
	RateLimitPerSecond   int
	DNSQueryThreshold    int
	LogDNSQueries        bool
	LimaHost             string
	ForensicsOnKill      bool // preserve a forensic copy before the responder's auto-kill deletes the container
	OnThreat             func(ThreatEvent)
	OnAction             func(action, message string) // Called when container is paused/killed
	OnError              func(error)                  // Called on non-fatal errors (avoids stdout corruption)
}

// ThreatEvent represents a detected network threat
type ThreatEvent struct {
	Timestamp   time.Time
	Level       ThreatLevel
	Category    string
	Title       string
	Description string
	Evidence    *NetworkEvent `json:"evidence,omitempty"`
}

// ThreatLevel represents the severity of a threat
type ThreatLevel string

// Threat levels, in increasing order of severity.
const (
	ThreatLevelInfo     ThreatLevel = "info"
	ThreatLevelWarning  ThreatLevel = "warning"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)
