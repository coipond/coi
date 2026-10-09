//go:build linux
// +build linux

package nftmonitor

import (
	"testing"
	"time"
)

func TestNetworkDetector_MetadataEndpoint(t *testing.T) {
	cfg := &Config{
		ContainerIP: "10.47.62.50",
	}
	nd := NewNetworkDetector(cfg)

	event := &NetworkEvent{
		Timestamp:   time.Now(),
		ContainerIP: "10.47.62.50",
		SrcIP:       "10.47.62.50",
		DstIP:       "169.254.169.254",
		DstPort:     80,
		Protocol:    "TCP",
	}

	threat := nd.Analyze(event)
	if threat == nil {
		t.Fatal("Expected threat for metadata endpoint, got nil")
		return // unreachable but helps staticcheck
	}
	if threat.Level != ThreatLevelCritical {
		t.Errorf("Expected CRITICAL level, got %s", threat.Level)
	}
	if threat.Title != "Metadata endpoint access" {
		t.Errorf("Expected 'Metadata endpoint access' title, got %q", threat.Title)
	}
}

func TestNetworkDetector_SuspiciousPorts(t *testing.T) {
	cfg := &Config{
		ContainerIP: "10.47.62.50",
	}
	nd := NewNetworkDetector(cfg)

	tests := []struct {
		port        int
		shouldAlert bool
	}{
		{4444, true},  // Metasploit default
		{5555, true},  // Common backdoor
		{1234, true},  // Reverse shell
		{31337, true}, // Leet port
		{12345, true}, // NetBus
		{6666, true},  // Various backdoors
		{6667, true},  // IRC
		{6697, true},  // IRC SSL
		{8080, true},  // HTTP alt
		{80, false},   // Normal HTTP
		{443, false},  // Normal HTTPS
		{22, false},   // SSH
		{53, false},   // DNS (handled separately)
		{123, false},  // NTP
		{25, false},   // SMTP
	}

	for _, tt := range tests {
		event := &NetworkEvent{
			Timestamp:   time.Now(),
			ContainerIP: "10.47.62.50",
			SrcIP:       "10.47.62.50",
			DstIP:       "1.2.3.4", // Non-RFC1918
			DstPort:     tt.port,
			Protocol:    "TCP",
		}

		threat := nd.Analyze(event)
		if tt.shouldAlert {
			if threat == nil {
				t.Errorf("Port %d: Expected threat, got nil", tt.port)
				continue
			}
			if threat.Level != ThreatLevelCritical {
				t.Errorf("Port %d: Expected CRITICAL level, got %s", tt.port, threat.Level)
			}
		} else {
			// Note: some ports may still trigger alerts (like DNS)
			if threat != nil && threat.Title == "Connection to suspicious port" {
				t.Errorf("Port %d: Should not alert as suspicious port, got %q", tt.port, threat.Title)
			}
		}
	}
}

func TestNetworkDetector_RFC1918(t *testing.T) {
	cfg := &Config{
		ContainerIP: "10.47.62.50",
	}
	nd := NewNetworkDetector(cfg)

	tests := []struct {
		name        string
		dstIP       string
		shouldAlert bool
	}{
		{"10.0.0.0/8 - start", "10.0.0.1", true},
		{"10.0.0.0/8 - middle", "10.128.0.1", true},
		{"10.0.0.0/8 - end", "10.255.255.254", true},
		{"172.16.0.0/12 - start", "172.16.0.1", true},
		{"172.16.0.0/12 - middle", "172.24.0.1", true},
		{"172.16.0.0/12 - end", "172.31.255.254", true},
		{"192.168.0.0/16 - start", "192.168.0.1", true},
		{"192.168.0.0/16 - end", "192.168.255.254", true},
		{"Public IP - Google DNS", "8.8.8.8", false},
		{"Public IP - Cloudflare", "1.1.1.1", false},
		{"Loopback", "127.0.0.1", false}, // Not RFC1918
		{"Not in 172.16/12 range", "172.32.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &NetworkEvent{
				Timestamp:   time.Now(),
				ContainerIP: "10.47.62.50",
				SrcIP:       "10.47.62.50",
				DstIP:       tt.dstIP,
				DstPort:     80,
				Protocol:    "TCP",
			}

			threat := nd.Analyze(event)
			if tt.shouldAlert {
				if threat == nil {
					t.Errorf("Expected threat for %s, got nil", tt.dstIP)
					return
				}
				if threat.Level != ThreatLevelHigh {
					t.Errorf("Expected HIGH level for RFC1918, got %s", threat.Level)
				}
			} else {
				if threat != nil && threat.Title == "Connection to private network" {
					t.Errorf("Should not alert as RFC1918 for %s", tt.dstIP)
				}
			}
		})
	}
}

func TestNetworkDetector_DNSQueryThreshold(t *testing.T) {
	cfg := &Config{
		ContainerIP:       "10.47.62.50",
		DNSQueryThreshold: 10,
		GatewayIP:         "8.8.8.8", // Use public DNS as gateway for test
	}
	nd := NewNetworkDetector(cfg)

	event := &NetworkEvent{
		Timestamp:   time.Now(),
		ContainerIP: "10.47.62.50",
		SrcIP:       "10.47.62.50",
		DstIP:       "8.8.8.8", // Same as gateway (expected DNS)
		DstPort:     53,
		Protocol:    "UDP",
	}

	// First 10 queries should not trigger alert
	for i := 0; i < 10; i++ {
		threat := nd.Analyze(event)
		if threat != nil {
			t.Errorf("Query %d: Should not alert within threshold, got %q", i+1, threat.Title)
		}
	}

	// 11th query should trigger alert
	threat := nd.Analyze(event)
	if threat == nil {
		t.Fatal("Expected threat for exceeding DNS threshold, got nil")
		return // unreachable but helps staticcheck
	}
	if threat.Level != ThreatLevelWarning {
		t.Errorf("Expected WARNING level for DNS threshold, got %s", threat.Level)
	}
	if threat.Title != "High DNS query volume" {
		t.Errorf("Expected 'High DNS query volume' title, got %q", threat.Title)
	}
}

func TestNetworkDetector_DNSToNonStandardServer(t *testing.T) {
	cfg := &Config{
		ContainerIP: "10.47.62.50",
		GatewayIP:   "10.47.62.1",
	}
	nd := NewNetworkDetector(cfg)

	// DNS query to non-gateway, non-allowlisted server
	event := &NetworkEvent{
		Timestamp:   time.Now(),
		ContainerIP: "10.47.62.50",
		SrcIP:       "10.47.62.50",
		DstIP:       "8.8.8.8", // Google DNS - not gateway
		DstPort:     53,
		Protocol:    "UDP",
	}

	threat := nd.Analyze(event)
	if threat == nil {
		t.Fatal("Expected threat for DNS to non-standard server, got nil")
		return // unreachable but helps staticcheck
	}
	if threat.Level != ThreatLevelWarning {
		t.Errorf("Expected WARNING level, got %s", threat.Level)
	}
	if threat.Title != "DNS query to non-standard server" {
		t.Errorf("Expected 'DNS query to non-standard server' title, got %q", threat.Title)
	}
}

func TestNetworkDetector_Allowlist(t *testing.T) {
	cfg := &Config{
		ContainerIP:  "10.47.62.50",
		AllowedCIDRs: []string{"1.1.1.0/24", "8.8.8.0/24"},
	}
	nd := NewNetworkDetector(cfg)

	tests := []struct {
		name        string
		dstIP       string
		shouldAlert bool
	}{
		{"Allowed - Cloudflare", "1.1.1.1", false},
		{"Allowed - Google DNS", "8.8.8.8", false},
		{"Not in allowlist", "9.9.9.9", true},
		{"Also not allowed", "142.250.189.206", true}, // google.com
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &NetworkEvent{
				Timestamp:   time.Now(),
				ContainerIP: "10.47.62.50",
				SrcIP:       "10.47.62.50",
				DstIP:       tt.dstIP,
				DstPort:     443,
				Protocol:    "TCP",
			}

			threat := nd.Analyze(event)
			if tt.shouldAlert {
				if threat == nil {
					t.Errorf("Expected threat for %s (not in allowlist), got nil", tt.dstIP)
					return
				}
				if threat.Title != "Unauthorized connection attempt" {
					t.Errorf("Expected 'Unauthorized connection attempt' title, got %q", threat.Title)
				}
			} else {
				if threat != nil {
					t.Errorf("Should not alert for allowlisted %s, got %q", tt.dstIP, threat.Title)
				}
			}
		})
	}
}

func TestNetworkDetector_NoFalsePositives(t *testing.T) {
	// Test that normal traffic doesn't trigger alerts
	cfg := &Config{
		ContainerIP: "10.47.62.50",
		// No allowlist, no gateway configured
	}
	nd := NewNetworkDetector(cfg)

	normalTraffic := []struct {
		name    string
		dstIP   string
		dstPort int
	}{
		{"HTTPS to Google", "142.250.189.206", 443},
		{"HTTP to example.com", "93.184.216.34", 80},
		{"SSH to public server", "203.0.113.10", 22},
		{"HTTPS to AWS", "54.239.28.85", 443},
	}

	for _, tt := range normalTraffic {
		t.Run(tt.name, func(t *testing.T) {
			event := &NetworkEvent{
				Timestamp:   time.Now(),
				ContainerIP: "10.47.62.50",
				SrcIP:       "10.47.62.50",
				DstIP:       tt.dstIP,
				DstPort:     tt.dstPort,
				Protocol:    "TCP",
			}

			threat := nd.Analyze(event)
			if threat != nil {
				t.Errorf("Normal traffic to %s:%d triggered alert: %q", tt.dstIP, tt.dstPort, threat.Title)
			}
		})
	}
}

func TestNetworkDetector_GatewayNotFalsePositive(t *testing.T) {
	cfg := &Config{
		ContainerIP: "10.47.62.50",
		GatewayIP:   "10.47.62.1", // RFC1918 gateway
	}
	nd := NewNetworkDetector(cfg)

	// Traffic to gateway should NOT trigger RFC1918 alert
	event := &NetworkEvent{
		Timestamp:   time.Now(),
		ContainerIP: "10.47.62.50",
		SrcIP:       "10.47.62.50",
		DstIP:       "10.47.62.1", // Same as gateway
		DstPort:     80,
		Protocol:    "TCP",
	}

	threat := nd.Analyze(event)
	if threat != nil && threat.Title == "Connection to private network" {
		t.Errorf("Gateway IP should not trigger RFC1918 alert, got: %q", threat.Title)
	}
}

func TestNetworkDetector_RFC1918StillAlertsWithGateway(t *testing.T) {
	cfg := &Config{
		ContainerIP: "10.47.62.50",
		GatewayIP:   "10.47.62.1", // Gateway is set
	}
	nd := NewNetworkDetector(cfg)

	// Non-gateway RFC1918 addresses should still trigger alert
	tests := []struct {
		name  string
		dstIP string
	}{
		{"Different 10.x address", "10.0.0.1"},
		{"172.16 address", "172.16.0.1"},
		{"192.168 address", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &NetworkEvent{
				Timestamp:   time.Now(),
				ContainerIP: "10.47.62.50",
				SrcIP:       "10.47.62.50",
				DstIP:       tt.dstIP,
				DstPort:     80,
				Protocol:    "TCP",
			}

			threat := nd.Analyze(event)
			if threat == nil {
				t.Errorf("Expected RFC1918 alert for %s (not gateway), got nil", tt.dstIP)
				return
			}
			if threat.Title != "Connection to private network" {
				t.Errorf("Expected 'Connection to private network' for %s, got %q", tt.dstIP, threat.Title)
			}
		})
	}
}

// A destination the firewall permits (a [[network.hosts]] LAN service on its
// port, possibly added at runtime) raises no private-network, allowlist or
// DNS-server alert. The exemption is port-aware, and C2-port detection still
// applies to the permitted host.
func TestNetworkDetector_FirewallPermittedDestination(t *testing.T) {
	permitted := func(ip string, port int) bool {
		return (ip == "10.50.0.100" && (port == 443 || port == 4444)) || (ip == "10.50.0.53" && port == 53)
	}
	nd := NewNetworkDetector(&Config{
		ContainerIP:          "10.47.62.50",
		GatewayIP:            "10.47.62.1",
		AllowedCIDRs:         []string{"140.82.112.3/32"},
		PermittedDestination: permitted,
	})
	event := func(dst string, port int) *NetworkEvent {
		return &NetworkEvent{
			Timestamp: time.Now(), ContainerIP: "10.47.62.50", SrcIP: "10.47.62.50",
			DstIP: dst, DstPort: port, Protocol: "TCP",
		}
	}
	if threat := nd.Analyze(event("10.50.0.100", 443)); threat != nil {
		t.Errorf("permitted LAN service should not alert, got %q", threat.Title)
	}
	if threat := nd.Analyze(event("10.50.0.53", 53)); threat != nil {
		t.Errorf("permitted LAN resolver should not alert, got %q", threat.Title)
	}
	for _, tc := range []struct {
		dst   string
		port  int
		title string
	}{
		{"10.50.0.100", 22, "Connection to private network"},
		{"10.50.0.101", 443, "Connection to private network"},
		{"10.50.0.100", 4444, "Connection to suspicious port"},
	} {
		threat := nd.Analyze(event(tc.dst, tc.port))
		if threat == nil || threat.Title != tc.title {
			t.Errorf("%s:%d: want %q, got %v", tc.dst, tc.port, tc.title, threat)
		}
	}
}

// Helper function tests
func TestIsRFC1918(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"172.15.0.1", false},  // Just outside 172.16/12
		{"172.32.0.1", false},  // Just outside 172.16/12
		{"8.8.8.8", false},     // Public
		{"1.1.1.1", false},     // Public
		{"127.0.0.1", false},   // Loopback (not RFC1918)
		{"169.254.0.1", false}, // Link-local (not RFC1918)
		{"invalid", false},     // Invalid IP
		{"", false},            // Empty
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := isRFC1918(tt.ip)
			if result != tt.expected {
				t.Errorf("isRFC1918(%q) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsSuspiciousPort(t *testing.T) {
	suspiciousPorts := []int{4444, 5555, 1234, 31337, 12345, 6666, 6667, 6697, 8080}
	normalPorts := []int{80, 443, 22, 25, 110, 143, 993, 465, 587, 3306, 5432}

	for _, port := range suspiciousPorts {
		if !isSuspiciousPort(port) {
			t.Errorf("Port %d should be suspicious", port)
		}
	}

	for _, port := range normalPorts {
		if isSuspiciousPort(port) {
			t.Errorf("Port %d should not be suspicious", port)
		}
	}
}

func TestInAllowlist(t *testing.T) {
	allowlist := []string{"10.0.0.0/8", "192.168.1.0/24"}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.1", true},
		{"192.168.1.254", true},
		{"192.168.2.1", false}, // Different subnet
		{"8.8.8.8", false},     // Not in allowlist
		{"invalid", false},     // Invalid IP
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := inAllowlist(tt.ip, allowlist)
			if result != tt.expected {
				t.Errorf("inAllowlist(%q) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}
