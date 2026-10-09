package nftmonitor

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// NetworkDetector analyzes network events for threats
type NetworkDetector struct {
	config        *Config
	dnsQueryCount map[string]int // containerIP -> count
	dnsQueryReset time.Time
	mu            sync.Mutex
}

// NewNetworkDetector creates a new network threat detector
func NewNetworkDetector(cfg *Config) *NetworkDetector {
	return &NetworkDetector{
		config:        cfg,
		dnsQueryCount: make(map[string]int),
		dnsQueryReset: time.Now(),
	}
}

// Analyze examines a network event and returns a threat if detected
func (nd *NetworkDetector) Analyze(event *NetworkEvent) *ThreatEvent {
	// Reset DNS query counters every minute
	nd.mu.Lock()
	if time.Since(nd.dnsQueryReset) > time.Minute {
		nd.dnsQueryCount = make(map[string]int)
		nd.dnsQueryReset = time.Now()
	}
	nd.mu.Unlock()

	// 1. RFC1918 addresses (should be blocked by firewall), except one on the
	// allowlist — a [[network.hosts]] LAN entry the firewall deliberately permits.
	if isRFC1918(event.DstIP) && event.DstIP != nd.config.GatewayIP && !inAllowlist(event.DstIP, nd.config.AllowedCIDRs) {
		return &ThreatEvent{
			Timestamp:   event.Timestamp,
			Level:       ThreatLevelHigh,
			Category:    "network",
			Title:       "Connection to private network",
			Description: fmt.Sprintf("RFC1918 address: %s:%d (should be blocked by firewall)", event.DstIP, event.DstPort),
			Evidence:    event,
		}
	}

	// 2. Metadata endpoint
	if event.DstIP == "169.254.169.254" {
		return &ThreatEvent{
			Timestamp:   event.Timestamp,
			Level:       ThreatLevelCritical,
			Category:    "network",
			Title:       "Metadata endpoint access",
			Description: "Attempted connection to cloud metadata endpoint",
			Evidence:    event,
		}
	}

	// 3. Suspicious ports (4444, 5555, 31337, etc.)
	if isSuspiciousPort(event.DstPort) {
		return &ThreatEvent{
			Timestamp:   event.Timestamp,
			Level:       ThreatLevelCritical,
			Category:    "network",
			Title:       "Connection to suspicious port",
			Description: fmt.Sprintf("C2/backdoor port %d to %s", event.DstPort, event.DstIP),
			Evidence:    event,
		}
	}

	// 4. Allowlist violations (if in allowlist mode)
	if len(nd.config.AllowedCIDRs) > 0 && !inAllowlist(event.DstIP, nd.config.AllowedCIDRs) {
		return &ThreatEvent{
			Timestamp:   event.Timestamp,
			Level:       ThreatLevelHigh,
			Category:    "network",
			Title:       "Unauthorized connection attempt",
			Description: fmt.Sprintf("IP not in allowlist: %s:%d", event.DstIP, event.DstPort),
			Evidence:    event,
		}
	}

	// 5. DNS query monitoring
	if event.DstPort == 53 {
		return nd.analyzeDNSQuery(event)
	}

	return nil
}

// analyzeDNSQuery checks DNS queries for anomalies
func (nd *NetworkDetector) analyzeDNSQuery(event *NetworkEvent) *ThreatEvent {
	// Track query frequency per container
	nd.mu.Lock()
	nd.dnsQueryCount[event.ContainerIP]++
	count := nd.dnsQueryCount[event.ContainerIP]
	nd.mu.Unlock()

	// Alert on high volume (potential DNS tunneling)
	if nd.config.DNSQueryThreshold > 0 && count > nd.config.DNSQueryThreshold {
		return &ThreatEvent{
			Timestamp: event.Timestamp,
			Level:     ThreatLevelWarning,
			Category:  "network",
			Title:     "High DNS query volume",
			Description: fmt.Sprintf("%d queries in last minute (threshold: %d) - potential DNS tunneling",
				count, nd.config.DNSQueryThreshold),
			Evidence: event,
		}
	}

	// Alert on queries to unexpected DNS servers
	// Allow gateway IP and allowlisted IPs
	if nd.config.GatewayIP != "" && event.DstIP != nd.config.GatewayIP {
		if !inAllowlist(event.DstIP, nd.config.AllowedCIDRs) {
			return &ThreatEvent{
				Timestamp: event.Timestamp,
				Level:     ThreatLevelWarning,
				Category:  "network",
				Title:     "DNS query to non-standard server",
				Description: fmt.Sprintf("Query to %s (expected: %s or allowlist)",
					event.DstIP, nd.config.GatewayIP),
				Evidence: event,
			}
		}
	}

	return nil
}

// isRFC1918 checks if IP is in private address space
func isRFC1918(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// inAllowlist checks if IP is in allowed CIDR ranges
func inAllowlist(ipStr string, allowedCIDRs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range allowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// isSuspiciousPort checks if port is commonly used for C2/backdoors
func isSuspiciousPort(port int) bool {
	// Common C2 and backdoor ports
	suspiciousPorts := []int{
		4444,  // Metasploit default
		5555,  // Common backdoor
		1234,  // Common reverse shell
		31337, // Elite/leet port
		12345, // NetBus
		6666,  // Various backdoors
		6667,  // IRC (sometimes C2)
		6697,  // IRC SSL
		8080,  // HTTP alt (when used for outbound)
	}

	for _, p := range suspiciousPorts {
		if port == p {
			return true
		}
	}

	return false
}
