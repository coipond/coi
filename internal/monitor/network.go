package monitor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// CollectNetworkStats collects network statistics and flags suspicious connections.
// It attempts to read /proc/<container-init-pid>/net/tcp[6] from the host so the
// data is scoped to the container's network namespace. If PID resolution or the
// namespaced reads fail, it falls back to host /proc/net/tcp[6] filtered by
// containerIP (best-effort; requires a non-empty containerIP to avoid returning
// all host connections).
func CollectNetworkStats(ctx context.Context, containerName, containerIP string, allowedCIDRs []string, permitted PermittedDestinationFunc, gateway func() string) (NetworkStats, error) {
	connections, pid, err := parseConnections(ctx, containerName, containerIP)
	if err != nil {
		return NetworkStats{}, err
	}

	// Flag suspicious connections
	suspicious := 0
	var local []*net.IPNet
	localRead := false
	for i := range connections {
		reason := checkSuspicious(connections[i], allowedCIDRs, permitted, gateway)
		if reason != "" && pid > 0 {
			if !localRead {
				local = containerLocalNets(fmt.Sprintf("/proc/%d/net/route", pid))
				localRead = true
			}
			if inNets(extractIP(connections[i].RemoteAddr), local) {
				reason = ""
			}
		}
		if reason != "" {
			connections[i].Suspicious = true
			connections[i].SuspectReason = reason
			suspicious++
		}
	}

	return NetworkStats{
		ActiveConnections: len(connections),
		Connections:       connections,
		SuspiciousCount:   suspicious,
	}, nil
}

// parseConnections reads the container's /proc/net/tcp[6] via the host-side
// namespaced path /proc/<container-init-pid>/net/tcp[6]. Falls back to the
// host's /proc/net/tcp + containerIP filter when PID resolution fails or when
// the namespaced paths cannot be read. The returned PID is the one whose
// namespaced paths were read, or 0 for the host fallback.
func parseConnections(ctx context.Context, containerName, containerIP string) ([]Connection, int, error) {
	pid, pidErr := GetContainerInitPID(ctx, containerName)
	if pidErr != nil && ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}

	if pid > 0 {
		// Prefer namespaced paths scoped to the container's network namespace.
		var connections []Connection
		namespacedOK := false

		tcp4Conns, err := parseProcNetTCP(fmt.Sprintf("/proc/%d/net/tcp", pid), "tcp")
		if err == nil {
			connections = append(connections, tcp4Conns...)
			namespacedOK = true
		}

		tcp6Conns, err := parseProcNetTCP(fmt.Sprintf("/proc/%d/net/tcp6", pid), "tcp6")
		if err == nil {
			connections = append(connections, tcp6Conns...)
			namespacedOK = true
		}

		udpConns, err := parseProcNetTCP(fmt.Sprintf("/proc/%d/net/udp", pid), "udp")
		if err == nil {
			connections = append(connections, udpConns...)
			namespacedOK = true
		}

		udp6Conns, err := parseProcNetTCP(fmt.Sprintf("/proc/%d/net/udp6", pid), "udp6")
		if err == nil {
			connections = append(connections, udp6Conns...)
			namespacedOK = true
		}

		if namespacedOK {
			return connections, pid, nil
		}
		// Namespaced paths unreadable — fall through to host fallback below.
	}

	// Fallback: host /proc/net/tcp[6] filtered by containerIP.
	// Require containerIP to avoid returning all host connections.
	if containerIP == "" {
		return nil, 0, nil
	}

	var connections []Connection

	tcp4Conns, err := parseProcNetTCP("/proc/net/tcp", "tcp")
	if err == nil {
		connections = append(connections, tcp4Conns...)
	}

	tcp6Conns, err := parseProcNetTCP("/proc/net/tcp6", "tcp6")
	if err == nil {
		connections = append(connections, tcp6Conns...)
	}

	udpConns, err := parseProcNetTCP("/proc/net/udp", "udp")
	if err == nil {
		connections = append(connections, udpConns...)
	}

	udp6Conns, err := parseProcNetTCP("/proc/net/udp6", "udp6")
	if err == nil {
		connections = append(connections, udp6Conns...)
	}

	filtered := make([]Connection, 0, len(connections))
	for _, conn := range connections {
		if strings.HasPrefix(conn.LocalAddr, containerIP+":") {
			filtered = append(filtered, conn)
		}
	}
	return filtered, 0, nil
}

// containerLocalNets returns the IPv4 networks that a /proc/<pid>/net/route
// table sends straight to an interface inside the container (a nested Docker
// bridge), so traffic to them never leaves it. The Incus NIC (eth0) and any
// interface with a default route are its uplink and are left out: hosts on the
// uplink subnet are outside the container. Errors give no networks.
func containerLocalNets(path string) []*net.IPNet {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	type route struct {
		iface string
		net   *net.IPNet
	}
	var direct []route
	uplink := map[string]bool{"lo": true, "eth0": true}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&unix.RTF_UP == 0 {
			continue
		}
		dest, err := parseHexIP(fields[1])
		if err != nil {
			continue
		}
		mask, err := parseHexIP(fields[7])
		if err != nil {
			continue
		}
		ipNet := &net.IPNet{IP: net.ParseIP(dest).To4(), Mask: net.IPMask(net.ParseIP(mask).To4())}
		if ones, _ := ipNet.Mask.Size(); ones == 0 {
			uplink[fields[0]] = true
			continue
		}
		if flags&unix.RTF_GATEWAY == 0 {
			direct = append(direct, route{iface: fields[0], net: ipNet})
		}
	}

	var local []*net.IPNet
	for _, r := range direct {
		if !uplink[r.iface] {
			local = append(local, r.net)
		}
	}
	return local
}

// inNets reports whether ipStr is in one of nets.
func inNets(ipStr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseProcNetTCP parses /proc/net/tcp or /proc/net/tcp6
func parseProcNetTCP(path, protocol string) ([]Connection, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var connections []Connection
	scanner := bufio.NewScanner(file)

	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse local address
		localAddr, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}

		// Parse remote address
		remoteAddr, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}

		// Parse state
		stateHex := fields[3]
		state := tcpStateFromHex(stateHex)

		// Parse UID
		uid, _ := strconv.Atoi(fields[7])

		connections = append(connections, Connection{
			Protocol:   protocol,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			State:      state,
			UID:        uid,
		})
	}

	return connections, scanner.Err()
}

// parseHexAddr converts hex address format to IP:port
func parseHexAddr(hexAddr string) (string, error) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid address format: %s", hexAddr)
	}

	// Parse IP
	ip, err := parseHexIP(parts[0])
	if err != nil {
		return "", err
	}

	// Parse port
	portHex := parts[1]
	port, err := strconv.ParseInt(portHex, 16, 64)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d", ip, port), nil
}

// parseHexIP converts hex IP to string
func parseHexIP(hexIP string) (string, error) {
	// Handle IPv4 (8 hex chars)
	if len(hexIP) == 8 {
		// Little-endian format
		ipInt, err := strconv.ParseUint(hexIP, 16, 32)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("%d.%d.%d.%d",
			ipInt&0xFF,
			(ipInt>>8)&0xFF,
			(ipInt>>16)&0xFF,
			(ipInt>>24)&0xFF,
		), nil
	}

	// Handle IPv6 (32 hex chars)
	if len(hexIP) == 32 {
		// Parse as 4 groups of 8 hex chars (little-endian per group)
		var parts []string
		for i := 0; i < 32; i += 8 {
			group := hexIP[i : i+8]
			// Reverse byte order within group
			reversed := ""
			for j := len(group) - 2; j >= 0; j -= 2 {
				reversed += group[j : j+2]
			}
			parts = append(parts, reversed)
		}

		// Convert to standard IPv6 format
		ipv6 := ""
		for i := 0; i < len(parts); i++ {
			if i > 0 {
				ipv6 += ":"
			}
			// Take 4 hex chars at a time
			for j := 0; j < len(parts[i]); j += 4 {
				if j > 0 {
					ipv6 += ":"
				}
				ipv6 += parts[i][j : j+4]
			}
		}

		// Simplify using net package
		ip := net.ParseIP(ipv6)
		if ip == nil {
			return ipv6, nil // Return as-is if parse fails
		}
		return ip.String(), nil
	}

	return "", fmt.Errorf("invalid IP format: %s", hexIP)
}

// tcpStateFromHex converts hex TCP state to string
func tcpStateFromHex(hexState string) string {
	state, err := strconv.ParseInt(hexState, 16, 32)
	if err != nil {
		return "UNKNOWN"
	}

	states := []string{
		"", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
		"FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK",
		"LISTEN", "CLOSING",
	}

	if state >= 0 && int(state) < len(states) {
		return states[state]
	}

	return "UNKNOWN"
}

// reasonNotInAllowlist flags a destination outside the network allowlist.
const reasonNotInAllowlist = "IP not in network allowlist"

// checkSuspicious determines if a connection is suspicious. permitted (may be
// nil) reports destinations the firewall deliberately accepts; those are exempt
// from the private-network and allowlist checks, but not from the others.
// gateway (may be nil) returns the container's bridge gateway, asked only for a
// DNS or DHCP port when allowedCIDRs is set.
func checkSuspicious(conn Connection, allowedCIDRs []string, permitted PermittedDestinationFunc, gateway func() string) string {
	// Skip local connections (LISTEN state or localhost)
	if conn.State == "LISTEN" {
		return ""
	}

	// Loopback and unspecified addresses never leave the container.
	remoteIP := extractIP(conn.RemoteAddr)
	port := extractPort(conn.RemoteAddr)
	ip := net.ParseIP(remoteIP)
	if ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return ""
	}
	// The bridge's DNS and DHCP service: a resolver or DHCP client in the
	// container keeps a socket to it even where the firewall drops the packets.
	// By port only: any other port on the gateway is still checked. Without an
	// allowlist nothing below flags these ports, so the gateway is not asked.
	if len(allowedCIDRs) > 0 && (port == 53 || (port == 67 && strings.HasPrefix(conn.Protocol, "udp"))) && gateway != nil {
		if gw := net.ParseIP(gateway()); gw != nil && gw.Equal(ip) {
			return ""
		}
	}

	// A destination the firewall accepts on this port (a [[network.hosts]] LAN
	// service) is neither a private-network leak nor an allowlist violation. The
	// match is port-aware, so a probe of another port on that host still counts.
	// Only asked once a check would otherwise fire.
	firewallPermits := func() bool { return permitted != nil && permitted(conn.Protocol, remoteIP, port) }

	// Check RFC1918 addresses only when network is restricted (allowedCIDRs not empty)
	// In "open" network mode (no restrictions), RFC1918 addresses are expected/allowed.
	if len(allowedCIDRs) > 0 && isRFC1918(remoteIP) && !firewallPermits() {
		return "RFC1918 private address (should be blocked by firewall)"
	}

	// Check metadata endpoint
	if remoteIP == "169.254.169.254" {
		return "Cloud metadata endpoint access"
	}

	// Check allowlist (if network is restricted)
	if len(allowedCIDRs) > 0 && !inAllowlist(remoteIP, allowedCIDRs) && !firewallPermits() {
		return reasonNotInAllowlist
	}

	// Check suspicious ports
	if isSuspiciousPort(port) {
		return fmt.Sprintf("Suspicious port: %d (common C2/backdoor port)", port)
	}

	return ""
}

// extractIP extracts IP address from "IP:port" string
func extractIP(addr string) string {
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// extractPort extracts port from "IP:port" string
func extractPort(addr string) int {
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		port, _ := strconv.Atoi(addr[idx+1:])
		return port
	}
	return 0
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
