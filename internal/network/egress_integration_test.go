//go:build integration

package network

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/logger"
)

// linesWithComment returns the nft rule lines carrying this container's coi-<ip>
// comment, so assertions bind to THIS test's rules rather than any leftover or
// concurrent container's rules in the shared chain.
func linesWithComment(rules, containerIP string) []string {
	comment := `comment "coi-` + containerIP + `"`
	var out []string
	for _, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, comment) {
			out = append(out, line)
		}
	}
	return out
}

// TestAllowlistModeAllowedPorts_Integration verifies that allowed_ports in
// allowlist mode scopes the set-accept rules to those destination ports: an
// allowlisted CIDR becomes reachable on 80/443 only, carrying a `th dport` match.
func TestAllowlistModeAllowedPorts_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	const testCIDR = "203.0.113.0/24" // TEST-NET-3 (RFC 5737)

	containerName := "coi-allowlist-ports-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() { cleanupTestContainer(t, containerName) })

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}
	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("Failed to launch container: %v", err)
	}
	time.Sleep(3 * time.Second)

	containerIP, err := GetContainerIP(containerName)
	if err != nil {
		t.Fatalf("Failed to get container IP: %v", err)
	}

	netCfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{testCIDR},
		AllowedPorts:   []int{80, 443},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		t.Fatalf("Failed to list nft chain: %v", err)
	}
	rules := string(output)
	t.Logf("nft chain:\n%s", rules)

	// Bind to the set-accept line for this container that carries the port match.
	var acceptLine string
	for _, line := range linesWithComment(rules, containerIP) {
		if strings.Contains(line, "@coi_s_") && strings.Contains(line, "accept") && strings.Contains(line, "dport") {
			acceptLine = line
			break
		}
	}
	if acceptLine == "" {
		t.Fatalf("expected a port-scoped static-set accept rule with a dport match:\n%s", rules)
	}
	if !strings.Contains(acceptLine, "443") || !strings.Contains(acceptLine, "80") {
		t.Errorf("expected dport 80/443 on the allowlist accept rule, got:\n%s", acceptLine)
	}

	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Errorf("Teardown failed: %v", err)
	}
	verifyTeardownRemovesRules(t, containerIP)
}

// TestRestrictedModeDNSPinAndPortCap_Integration exercises the user's real target
// setup: restricted mode with a pinned resolver (dns_servers) and an egress port
// cap (allowed_ports). It asserts the pinned resolver is accepted on :53, all
// other :53 is rejected, the internet egress is capped to the allowed ports, and
// a default-deny closes the chain — then that teardown removes everything.
func TestRestrictedModeDNSPinAndPortCap_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	// TEST-NET-3 (RFC 5737): documentation-only, never routed — a safe, unique
	// stand-in for a pinned Pi-hole address.
	const pinnedDNS = "203.0.113.53"

	containerName := "coi-restricted-dns-ports-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() { cleanupTestContainer(t, containerName) })

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}
	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("Failed to launch container: %v", err)
	}
	time.Sleep(3 * time.Second)

	containerIP, err := GetContainerIP(containerName)
	if err != nil {
		t.Fatalf("Failed to get container IP: %v", err)
	}

	netCfg := &config.NetworkConfig{
		Mode:         config.NetworkModeRestricted,
		DNSServers:   []string{pinnedDNS},
		AllowedPorts: []int{80, 443},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		t.Fatalf("Failed to list nft chain: %v", err)
	}
	rules := string(output)
	t.Logf("nft chain:\n%s", rules)

	lines := linesWithComment(rules, containerIP)
	if len(lines) == 0 {
		t.Fatalf("no rules found for container %s:\n%s", containerIP, rules)
	}

	var (
		dnsPinAccept bool // accept :53 to the pinned resolver
		dnsReject    bool // reject :53 to everything else
		portCap      bool // port-capped internet accept
		defaultDeny  bool // final catch-all reject
	)
	for _, line := range lines {
		hasDport53 := strings.Contains(line, "dport 53")
		switch {
		case hasDport53 && strings.Contains(line, pinnedDNS) && strings.Contains(line, "accept"):
			dnsPinAccept = true
		case hasDport53 && strings.Contains(line, "reject"):
			dnsReject = true
		case strings.Contains(line, "dport") && strings.Contains(line, "443") &&
			strings.Contains(line, "80") && strings.Contains(line, "accept"):
			portCap = true
		case strings.Contains(line, "reject") && !hasDport53 && !strings.Contains(line, "/"):
			// The default deny is a bare `ip saddr <ip> ... reject` with no daddr and
			// no dport 53 — distinguishing it from the RFC1918 and DNS rejects.
			defaultDeny = true
		}
	}

	if !dnsPinAccept {
		t.Errorf("expected an accept rule for pinned resolver %s on :53:\n%s", pinnedDNS, rules)
	}
	if !dnsReject {
		t.Errorf("expected a reject rule for :53 to non-pinned resolvers:\n%s", rules)
	}
	if !portCap {
		t.Errorf("expected a port-capped internet accept (dport 80/443):\n%s", rules)
	}
	if !defaultDeny {
		t.Errorf("expected a default-deny reject closing the chain:\n%s", rules)
	}

	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Errorf("Teardown failed: %v", err)
	}
	verifyTeardownRemovesRules(t, containerIP)
}

// setupNetForContainer is the shared launch+setup boilerplate for the
// rule-assertion integration tests below. It launches a fresh container, runs
// SetupForContainer with cfg, returns the container IP and the resulting forward
// chain text, and registers teardown+cleanup.
func setupNetForContainer(t *testing.T, containerName string, cfg *config.NetworkConfig) (string, string) {
	t.Helper()
	mgr := container.NewManager(containerName)
	t.Cleanup(func() { cleanupTestContainer(t, containerName) })

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}
	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("launch container: %v", err)
	}
	time.Sleep(3 * time.Second)

	containerIP, err := GetContainerIP(containerName)
	if err != nil {
		t.Fatalf("get container IP: %v", err)
	}

	netMgr := NewManager(cfg, logger.NewDiscard())
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer: %v", err)
	}
	t.Cleanup(func() { _ = netMgr.Teardown(context.Background(), containerName) })

	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		t.Fatalf("list nft chain: %v", err)
	}
	return containerIP, string(output)
}

// TestRestrictedModeMultipleDNSPins_Integration verifies each pinned resolver
// gets its own :53 accept and a single :53 reject closes the rest.
func TestRestrictedModeMultipleDNSPins_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	servers := []string{"203.0.113.10", "203.0.113.11"}
	containerIP, rules := setupNetForContainer(t, "coi-restricted-multi-dns", &config.NetworkConfig{
		Mode:       config.NetworkModeRestricted,
		DNSServers: servers,
	})
	lines := linesWithComment(rules, containerIP)

	var accepts, rejects int
	for _, line := range lines {
		if !strings.Contains(line, "dport 53") {
			continue
		}
		if strings.Contains(line, "accept") {
			accepts++
		}
		if strings.Contains(line, "reject") {
			rejects++
		}
	}
	if accepts != len(servers) {
		t.Errorf("expected %d :53 accept rules (one per pinned resolver), got %d:\n%s", len(servers), accepts, rules)
	}
	if rejects != 1 {
		t.Errorf("expected exactly 1 :53 reject rule, got %d:\n%s", rejects, rules)
	}
	for _, s := range servers {
		if !strings.Contains(rules, s) {
			t.Errorf("expected an accept rule for pinned resolver %s:\n%s", s, rules)
		}
	}
}

// TestRestrictedModeSinglePortCap_Integration verifies a single allowed port is
// emitted correctly (nft normalises `{ 8080 }` to `dport 8080`) and that a
// default-deny closes the chain.
func TestRestrictedModeSinglePortCap_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	containerIP, rules := setupNetForContainer(t, "coi-restricted-single-port", &config.NetworkConfig{
		Mode:         config.NetworkModeRestricted,
		AllowedPorts: []int{8080},
	})
	lines := linesWithComment(rules, containerIP)

	var portAccept, defaultDeny bool
	for _, line := range lines {
		if strings.Contains(line, "dport 8080") && strings.Contains(line, "accept") {
			portAccept = true
		}
		if strings.Contains(line, "reject") && !strings.Contains(line, "dport") && !strings.Contains(line, "/") {
			defaultDeny = true
		}
	}
	if !portAccept {
		t.Errorf("expected a `dport 8080 accept` rule:\n%s", rules)
	}
	if !defaultDeny {
		t.Errorf("expected a default-deny reject after the port cap:\n%s", rules)
	}
}

// TestRestrictedModeNoEgressKeys_HistoricRules_Integration is the regression
// guard: with neither dns_servers nor allowed_ports set, restricted mode emits
// the historic blanket accept with NO dport match and NO extra default deny.
func TestRestrictedModeNoEgressKeys_HistoricRules_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	containerIP, rules := setupNetForContainer(t, "coi-restricted-historic", &config.NetworkConfig{
		Mode: config.NetworkModeRestricted,
	})
	lines := linesWithComment(rules, containerIP)

	// No port scoping anywhere for this container.
	for _, line := range lines {
		if strings.Contains(line, "dport") {
			t.Errorf("unexpected dport match with no egress keys set:\n%s", line)
		}
	}
	// The catch-all must be a bare accept: no daddr, no dport, and not the ICMP
	// or conntrack accept (those also lack a daddr but are not the blanket rule).
	var blanketAccept bool
	for _, line := range lines {
		if strings.Contains(line, "accept") && !strings.Contains(line, "daddr") &&
			!strings.Contains(line, "dport") && !strings.Contains(line, "icmp") &&
			!strings.Contains(line, "ct state") {
			blanketAccept = true
		}
	}
	if !blanketAccept {
		t.Errorf("expected the historic blanket `accept` rule:\n%s", rules)
	}
}

// TestAllowlistPortCapCoversBothSets_Integration verifies allowed_ports scopes
// BOTH the static and dynamic set-accept rules (not just one).
func TestAllowlistPortCapCoversBothSets_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	containerIP, rules := setupNetForContainer(t, "coi-allowlist-both-sets", &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{"203.0.113.0/24"},
		AllowedPorts:   []int{443},
	})
	lines := linesWithComment(rules, containerIP)

	var staticScoped, dynamicScoped bool
	for _, line := range lines {
		if !strings.Contains(line, "accept") || !strings.Contains(line, "dport") {
			continue
		}
		if strings.Contains(line, "@coi_s_") {
			staticScoped = true
		}
		if strings.Contains(line, "@coi_d_") {
			dynamicScoped = true
		}
	}
	if !staticScoped {
		t.Errorf("static-set accept rule is not port-scoped:\n%s", rules)
	}
	if !dynamicScoped {
		t.Errorf("dynamic-set accept rule is not port-scoped:\n%s", rules)
	}
}

// TestRestrictedAllowLocalRespectsPortCap_Integration verifies the fix for the
// review finding that allowed_ports did not constrain LAN traffic when
// allow_local_network_access was set. With both enabled, the RFC1918 allow rules
// must be port-scoped (carry a dport match), so the LAN is reachable only on the
// permitted ports — not all ports.
func TestRestrictedAllowLocalRespectsPortCap_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	yes := true
	containerIP, rules := setupNetForContainer(t, "coi-restricted-local-portcap", &config.NetworkConfig{
		Mode:                    config.NetworkModeRestricted,
		AllowLocalNetworkAccess: &yes,
		AllowedPorts:            []int{443},
	})
	lines := linesWithComment(rules, containerIP)

	var localAccepts, localAcceptsWithPort int
	for _, line := range lines {
		// The RFC1918 allow rules for local access (daddr is a private CIDR, accept).
		if !strings.Contains(line, "accept") {
			continue
		}
		if strings.Contains(line, "10.0.0.0/8") || strings.Contains(line, "172.16.0.0/12") ||
			strings.Contains(line, "192.168.0.0/16") {
			localAccepts++
			if strings.Contains(line, "dport") && strings.Contains(line, "443") {
				localAcceptsWithPort++
			}
		}
	}
	if localAccepts == 0 {
		t.Fatalf("expected RFC1918 local-access allow rules, found none:\n%s", rules)
	}
	if localAcceptsWithPort != localAccepts {
		t.Errorf("expected every LAN allow rule to be port-scoped to 443, but %d/%d were blanket "+
			"(all-ports) — allowed_ports must apply to the LAN:\n%s", localAccepts-localAcceptsWithPort, localAccepts, rules)
	}
}

// TestRestrictedAllowLocalNoPortCapIsBlanket_Integration is the parity guard for
// the fix: with allow_local_network_access but NO allowed_ports, the LAN allow
// rules stay the historic all-ports blanket accept (no dport match).
func TestRestrictedAllowLocalNoPortCapIsBlanket_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	yes := true
	containerIP, rules := setupNetForContainer(t, "coi-restricted-local-blanket", &config.NetworkConfig{
		Mode:                    config.NetworkModeRestricted,
		AllowLocalNetworkAccess: &yes,
	})
	lines := linesWithComment(rules, containerIP)

	var found bool
	for _, line := range lines {
		if !strings.Contains(line, "accept") {
			continue
		}
		if strings.Contains(line, "10.0.0.0/8") || strings.Contains(line, "172.16.0.0/12") ||
			strings.Contains(line, "192.168.0.0/16") {
			found = true
			if strings.Contains(line, "dport") {
				t.Errorf("LAN allow rule should be a blanket accept with no allowed_ports set, "+
					"but it carries a dport match:\n%s", line)
			}
		}
	}
	if !found {
		t.Fatalf("expected blanket RFC1918 local-access allow rules, found none:\n%s", rules)
	}
}

// TestRestrictedDNSPinFiltersLocalOn53_Integration verifies that dns_servers
// filters LAN :53 too (finding 2): even with allow_local_network_access, the DNS
// pin reject precedes the RFC1918 allow, so an unpinned LAN resolver is blocked on
// :53 while the pinned LAN resolver (listed by exact IP) stays reachable. This is
// the consistent counterpart to the port cap applying to the LAN.
func TestRestrictedDNSPinFiltersLocalOn53_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	const lanResolver = "192.168.222.53" // a pinned LAN resolver (RFC1918)
	yes := true
	containerIP, rules := setupNetForContainer(t, "coi-restricted-local-dnspin", &config.NetworkConfig{
		Mode:                    config.NetworkModeRestricted,
		AllowLocalNetworkAccess: &yes,
		DNSServers:              []string{lanResolver},
	})
	lines := linesWithComment(rules, containerIP)

	pinAcceptIdx, pinRejectIdx, localAcceptIdx := -1, -1, -1
	for i, line := range lines {
		if pinAcceptIdx == -1 && strings.Contains(line, lanResolver) &&
			strings.Contains(line, "dport 53") && strings.Contains(line, "accept") {
			pinAcceptIdx = i
		}
		if pinRejectIdx == -1 && strings.Contains(line, "dport 53") && strings.Contains(line, "reject") {
			pinRejectIdx = i
		}
		if localAcceptIdx == -1 && strings.Contains(line, "accept") &&
			(strings.Contains(line, "10.0.0.0/8") || strings.Contains(line, "192.168.0.0/16")) {
			localAcceptIdx = i
		}
	}
	if pinAcceptIdx == -1 {
		t.Fatalf("pinned LAN resolver %s must be accepted on :53:\n%s", lanResolver, rules)
	}
	if pinRejectIdx == -1 {
		t.Fatalf("expected a :53 reject rule for unpinned resolvers:\n%s", rules)
	}
	if localAcceptIdx == -1 {
		t.Fatalf("expected RFC1918 local-access allow rules:\n%s", rules)
	}
	// Order: pinned :53 accept  <  :53 reject  <  LAN allow. So a pinned LAN resolver
	// works on :53, every other :53 (including LAN) is rejected, and the LAN allow
	// only governs non-53 traffic.
	if pinAcceptIdx >= pinRejectIdx || pinRejectIdx >= localAcceptIdx {
		t.Errorf("expected order pinAccept(%d) < pinReject(%d) < localAccept(%d) so the DNS pin "+
			"filters LAN :53 while the pinned resolver stays reachable:\n%s",
			pinAcceptIdx, pinRejectIdx, localAcceptIdx, rules)
	}
}

// TestRestrictedModeDNSPinOrderedBeforeRFC1918_Integration guards the
// security-critical ordering: a pinned resolver on the LAN must have its :53
// accept installed BEFORE the RFC1918 block, or the block would shadow it and the
// container could never reach its own resolver. Uses a private-range pinned IP
// with block_private_networks on, then asserts the accept precedes the reject.
func TestRestrictedModeDNSPinOrderedBeforeRFC1918_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	const lanResolver = "192.168.222.53" // RFC1918, unlikely to collide
	yes := true

	containerIP, rules := setupNetForContainer(t, "coi-restricted-dns-order", &config.NetworkConfig{
		Mode:                 config.NetworkModeRestricted,
		DNSServers:           []string{lanResolver},
		BlockPrivateNetworks: &yes,
	})
	lines := linesWithComment(rules, containerIP)

	pinIdx, rfcIdx := -1, -1
	for i, line := range lines {
		if pinIdx == -1 && strings.Contains(line, lanResolver) &&
			strings.Contains(line, "dport 53") && strings.Contains(line, "accept") {
			pinIdx = i
		}
		if rfcIdx == -1 && strings.Contains(line, "192.168.0.0/16") && strings.Contains(line, "reject") {
			rfcIdx = i
		}
	}
	if pinIdx == -1 {
		t.Fatalf("no :53 accept rule found for pinned LAN resolver %s:\n%s", lanResolver, rules)
	}
	if rfcIdx == -1 {
		t.Fatalf("no RFC1918 (192.168.0.0/16) reject rule found:\n%s", rules)
	}
	if pinIdx >= rfcIdx {
		t.Errorf("DNS pin accept (idx %d) must precede the RFC1918 reject (idx %d), or the LAN resolver is shadowed:\n%s",
			pinIdx, rfcIdx, rules)
	}
}

// TestAllowlistModeRejectsDNSServers_Integration verifies that combining
// dns_servers with allowlist mode is refused: allowlist mode blocks all DNS by
// design, so re-opening :53 to a pinned resolver would reintroduce exactly the
// host/container divergence the mode prevents. No container launch is required —
// the guard fires before any container state is touched.
func TestAllowlistModeRejectsDNSServers_Integration(t *testing.T) {
	if !NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	netCfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{"203.0.113.0/24"},
		DNSServers:     []string{"203.0.113.53"},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())

	err := netMgr.SetupForContainer(context.Background(), "coi-nonexistent-dnspin-guard")
	if err == nil {
		t.Fatal("expected SetupForContainer to fail when dns_servers is set in allowlist mode")
	}
	if !strings.Contains(err.Error(), "dns_servers") || !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("expected a dns_servers/allowlist incompatibility error, got: %v", err)
	}
}
