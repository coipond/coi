package health

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/monitor"
	"github.com/mensfeld/coi/internal/network"
	"github.com/mensfeld/coi/internal/vmhost"
)

// CheckNetworkBridge verifies the network bridge is configured
func CheckNetworkBridge() HealthCheck {
	networkName, err := network.GetIncusBridgeName()
	if err != nil {
		return HealthCheck{
			Name:    "network_bridge",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Could not determine bridge name: %v", err),
		}
	}

	// Get network configuration
	networkOutput, err := container.IncusOutput("network", "show", networkName)
	if err != nil {
		return HealthCheck{
			Name:    "network_bridge",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not get network info for %s: %v", networkName, err),
		}
	}

	// Parse IPv4 address
	var ipv4Address string
	for _, line := range strings.Split(networkOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ipv4.address:") {
			ipv4Address = strings.TrimSpace(strings.TrimPrefix(line, "ipv4.address:"))
			break
		}
	}

	if ipv4Address == "" || ipv4Address == "none" {
		return HealthCheck{
			Name:    "network_bridge",
			Status:  StatusFailed,
			Message: fmt.Sprintf("%s has no IPv4 address", networkName),
		}
	}

	return HealthCheck{
		Name:    "network_bridge",
		Status:  StatusOK,
		Message: fmt.Sprintf("%s (%s)", networkName, ipv4Address),
		Details: map[string]interface{}{
			"name": networkName,
			"ipv4": ipv4Address,
		},
	}
}

// CheckIPForwarding verifies IP forwarding is enabled
func CheckIPForwarding() HealthCheck {
	// On macOS, IP forwarding works differently
	if runtime.GOOS == "darwin" {
		return HealthCheck{
			Name:    "ip_forwarding",
			Status:  StatusOK,
			Message: "macOS - managed by Incus",
		}
	}

	// Read /proc/sys/net/ipv4/ip_forward
	content, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return HealthCheck{
			Name:    "ip_forwarding",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not check: %v", err),
		}
	}

	value := strings.TrimSpace(string(content))
	if value == "1" {
		return HealthCheck{
			Name:    "ip_forwarding",
			Status:  StatusOK,
			Message: "Enabled",
		}
	}

	return HealthCheck{
		Name:    "ip_forwarding",
		Status:  StatusWarning,
		Message: "Disabled (may affect container networking)",
	}
}

// CheckNft verifies nft availability and masquerade configuration
func CheckNft(netCfg config.NetworkConfig) HealthCheck {
	mode := netCfg.Mode
	sudoAllowed := netCfg.SudoAllowed()
	installed := network.NftInstalled()
	// NftUsable returns false (without probing sudo) when use_sudo=false — a user
	// who opted out of Coi invoking sudo at all.
	available := network.NftUsable(&netCfg)
	masquerade := network.MasqueradeEnabled()
	isColima := vmhost.Detect() == vmhost.KindLimaLike

	details := map[string]interface{}{
		"nft_installed": installed,
		"nft_available": available,
		"masquerade":    masquerade,
		"colima":        isColima,
		"use_sudo":      sudoAllowed,
	}

	if mode == config.NetworkModeOpen {
		return HealthCheck{
			Name:    "nft",
			Status:  StatusOK,
			Message: "nft not required for open mode",
			Details: details,
		}
	}

	// use_sudo=false with a mode that needs nft is a deliberate opt-out paired
	// with an incompatible mode. Surface it as a warning (not a hard failure)
	// pointing at the fix, rather than nagging about configuring sudo.
	if !sudoAllowed {
		return HealthCheck{
			Name:    "nft",
			Status:  StatusWarning,
			Message: fmt.Sprintf("use_sudo=false but network mode is %q, which needs nft — set [network] mode = \"open\" (restricted/allowlist require passwordless sudo)", mode),
			Details: details,
		}
	}

	// Required for restricted/allowlist modes
	if !installed {
		message := fmt.Sprintf("nft not installed (required for %s mode) — install with: sudo apt install nftables", mode)
		if isColima {
			message = "nft not installed — on Colima, set mode = \"open\" in [network] section of your config.toml"
		}
		return HealthCheck{
			Name:    "nft",
			Status:  StatusFailed,
			Message: message,
			Details: details,
		}
	}

	if !available {
		message := "nft installed but passwordless sudo not configured — run: coi health --fix"
		if isColima {
			message = "nft sudo not configured — on Colima, set mode = \"open\" in [network] section of your config.toml"
		}
		return HealthCheck{
			Name:    "nft",
			Status:  StatusFailed,
			Message: message,
			Details: details,
		}
	}

	if !masquerade {
		return HealthCheck{
			Name:    "nft",
			Status:  StatusWarning,
			Message: "Incus bridge NAT (masquerade) not enabled — containers may not reach the internet. Check with: incus network get incusbr0 ipv4.nat",
			Details: details,
		}
	}

	return HealthCheck{
		Name:    "nft",
		Status:  StatusOK,
		Message: fmt.Sprintf("nft available, Incus bridge NAT enabled (%s mode available)", mode),
		Details: details,
	}
}

// CheckUFWConflict checks if ufw is active with a DROP FORWARD policy that
// would block container traffic. With nft-based Coi, ufw and Coi can coexist
// as long as bridge forwarding rules are in place.
func CheckUFWConflict() HealthCheck {
	ufwInstalled := network.UfwInstalled()
	ufwActive := ufwInstalled && network.UfwActive()
	forwardDrop := network.ForwardPolicyIsDrop()

	details := map[string]interface{}{
		"ufw_installed":       ufwInstalled,
		"ufw_active":          ufwActive,
		"forward_policy_drop": forwardDrop,
	}

	if !ufwActive {
		return HealthCheck{
			Name:    "ufw_conflict",
			Status:  StatusOK,
			Message: "ufw is not active",
			Details: details,
		}
	}

	if forwardDrop {
		return HealthCheck{
			Name:    "ufw_conflict",
			Status:  StatusWarning,
			Message: "ufw is active and FORWARD policy is DROP — coi will add iptables bridge rules automatically to ensure containers can reach the network",
			Details: details,
		}
	}

	return HealthCheck{
		Name:    "ufw_conflict",
		Status:  StatusOK,
		Message: "ufw is active but FORWARD policy is not DROP — no conflict with Coi",
		Details: details,
	}
}

// CheckBridgeForwardRules checks whether the Incus bridge has iptables FORWARD
// ACCEPT rules in place when the FORWARD chain policy is DROP.  When the policy
// is ACCEPT (the common case) no per-bridge rules are needed and the check
// returns OK regardless of whether rules are present.
func CheckBridgeForwardRules() HealthCheck {
	hasRules, bridgeName, err := network.BridgeInTrustedZone()
	if err != nil {
		return HealthCheck{
			Name:    "bridge_forward_rules",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not check bridge forwarding rules: %v", err),
		}
	}

	forwardDrop := network.ForwardPolicyIsDrop()

	details := map[string]interface{}{
		"bridge_name":         bridgeName,
		"has_forward_rules":   hasRules,
		"forward_policy_drop": forwardDrop,
	}

	if !hasRules && forwardDrop {
		return HealthCheck{
			Name:    "bridge_forward_rules",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Bridge %s has no iptables FORWARD rules and FORWARD policy is DROP — rules are added automatically on first container start", bridgeName),
			Details: details,
		}
	}

	return HealthCheck{
		Name:    "bridge_forward_rules",
		Status:  StatusOK,
		Message: fmt.Sprintf("Bridge %s forwarding OK", bridgeName),
		Details: details,
	}
}

// CheckIptablesSudo verifies passwordless sudo for iptables, which Coi uses
// for bridge FORWARD rule inspection and management regardless of whether nft
// is also available.
func CheckIptablesSudo() HealthCheck {
	if runtime.GOOS == "darwin" {
		return HealthCheck{
			Name:    "iptables_sudo",
			Status:  StatusOK,
			Message: "macOS — not required",
		}
	}

	if !network.SudoEnabled() {
		return HealthCheck{
			Name:    "iptables_sudo",
			Status:  StatusOK,
			Message: "skipped — [network] use_sudo = false (Coi does not invoke sudo)",
		}
	}

	iptablesPath, err := exec.LookPath("iptables")
	if err != nil {
		return HealthCheck{
			Name:    "iptables_sudo",
			Status:  StatusOK,
			Message: "iptables not installed — not required",
		}
	}

	if exec.Command("sudo", "-n", iptablesPath, "-L", "FORWARD", "-n").Run() != nil {
		return HealthCheck{
			Name:    "iptables_sudo",
			Status:  StatusWarning,
			Message: fmt.Sprintf(`Passwordless sudo not configured for iptables — run: echo "$USER ALL=(ALL) NOPASSWD: %s" | sudo tee /etc/sudoers.d/coi-iptables && sudo chmod 0440 /etc/sudoers.d/coi-iptables`, iptablesPath),
		}
	}

	return HealthCheck{
		Name:    "iptables_sudo",
		Status:  StatusOK,
		Message: "Passwordless sudo configured for iptables",
	}
}

// CheckDNS verifies DNS resolution is working
func CheckDNS() HealthCheck {
	// Try to resolve a well-known domain
	testDomain := "api.anthropic.com"

	ips, err := net.LookupIP(testDomain)
	if err != nil {
		return HealthCheck{
			Name:    "dns_resolution",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Failed to resolve %s: %v", testDomain, err),
		}
	}

	if len(ips) == 0 {
		return HealthCheck{
			Name:    "dns_resolution",
			Status:  StatusWarning,
			Message: fmt.Sprintf("No IPs found for %s", testDomain),
		}
	}

	return HealthCheck{
		Name:    "dns_resolution",
		Status:  StatusOK,
		Message: fmt.Sprintf("Working (%s -> %d IPs)", testDomain, len(ips)),
		Details: map[string]interface{}{
			"test_domain": testDomain,
			"ip_count":    len(ips),
		},
	}
}

// getContainerGatewayIPFromProc reads the container's default gateway from
// /proc/<init-pid>/net/route on the host. This avoids running ip route inside
// the container, where the output could be influenced by a compromised binary.
func getContainerGatewayIPFromProc(containerName string) (string, error) {
	initPID, err := monitor.GetContainerInitPID(context.Background(), containerName)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/route", initPID))
	if err != nil {
		return "", err
	}
	return parseDefaultGatewayFromProcRoute(string(data))
}

// parseDefaultGatewayFromProcRoute extracts the default gateway IP from the
// content of /proc/<pid>/net/route. Gateway addresses are stored as
// little-endian hex 32-bit integers, e.g. "010080AC" → 172.128.0.1.
// When multiple default routes exist the one with the lowest metric is used.
// Routes with a zero gateway (direct/connected routes) are skipped.
// Kept separate so it can be unit-tested without a live container.
func parseDefaultGatewayFromProcRoute(content string) (string, error) {
	// fields indices: 0=Iface 1=Destination 2=Gateway 3=Flags 4=RefCnt
	//                 5=Use 6=Metric 7=Mask ...
	const (
		colDest    = 1
		colGateway = 2
		colMetric  = 6
		minFields  = 7
	)

	bestMetric := ^uint64(0) // max uint64
	bestGateway := ""

	for i, line := range strings.Split(content, "\n") {
		if i == 0 {
			continue // skip header
		}
		fields := strings.Fields(line)
		if len(fields) < minFields {
			continue
		}
		if fields[colDest] != "00000000" {
			continue // not a default route
		}
		if fields[colGateway] == "00000000" {
			continue // direct-link default, no usable gateway
		}
		n, err := strconv.ParseUint(fields[colGateway], 16, 32)
		if err != nil {
			continue
		}
		metric, _ := strconv.ParseUint(fields[colMetric], 16, 32)
		if bestGateway == "" || metric < bestMetric {
			bestMetric = metric
			ip := net.IP{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)} //nolint:gosec // G115: n fits in uint32 (ParseUint bitSize=32)
			bestGateway = ip.String()
		}
	}

	if bestGateway == "" {
		return "", fmt.Errorf("no usable default gateway found in /proc/net/route")
	}
	return bestGateway, nil
}

// CheckDockerForwardPolicy checks whether Docker has set the iptables FORWARD
// chain policy to DROP and reports whether coi can handle it
func CheckDockerForwardPolicy() HealthCheck {
	dockerRunning := network.IsDockerRunning()
	forwardDrop := network.ForwardPolicyIsDrop()
	nftAvailable := network.NftAvailable()
	iptablesAvailable := network.IptablesAvailable()

	details := map[string]interface{}{
		"docker_running":      dockerRunning,
		"forward_policy_drop": forwardDrop,
		"nft_available":       nftAvailable,
		"iptables_available":  iptablesAvailable,
	}

	if !dockerRunning {
		return HealthCheck{
			Name:    "docker_forward_policy",
			Status:  StatusOK,
			Message: "Docker not detected",
			Details: details,
		}
	}

	if !forwardDrop {
		return HealthCheck{
			Name:    "docker_forward_policy",
			Status:  StatusOK,
			Message: "Docker running, FORWARD policy is not DROP",
			Details: details,
		}
	}

	// FORWARD is DROP
	if nftAvailable {
		return HealthCheck{
			Name:    "docker_forward_policy",
			Status:  StatusOK,
			Message: "Docker FORWARD DROP detected — nft bridge rules will handle it",
			Details: details,
		}
	}

	if iptablesAvailable {
		return HealthCheck{
			Name:    "docker_forward_policy",
			Status:  StatusWarning,
			Message: "Docker FORWARD DROP detected, nft not available — coi will use iptables fallback automatically",
			Details: details,
		}
	}

	return HealthCheck{
		Name:    "docker_forward_policy",
		Status:  StatusFailed,
		Message: "Docker FORWARD DROP detected, no nft or iptables — containers cannot reach internet",
		Details: details,
	}
}
