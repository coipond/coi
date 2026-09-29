//go:build integration

package network

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/logger"
)

// These are true end-to-end tests: they drive real TCP connections FROM INSIDE
// the container and observe whether the egress policy allows or rejects them —
// rather than asserting on nft rule text. Each probe targets a raw public IP so
// no DNS resolution is involved, and every test first confirms baseline
// connectivity (skipping when CI has no egress) so a network-less runner can
// never turn "no connectivity" into a false pass.
//
// Well-known always-on endpoints used as targets:
//   1.1.1.1 — Cloudflare: listens on 80, 443 and 53
//   8.8.8.8 — Google:     listens on 443 and 53
//
// Rejected ports fail fast (the rules use `reject`, which returns RST/ICMP), so
// the `timeout` guard below only ever trips on a genuine drop, not on a normal
// block.

// containerCanConnect reports whether a TCP connection from inside the container
// to host:port completes within a few seconds. It uses bash's /dev/tcp, so it
// needs no extra tooling in the image.
func containerCanConnect(t *testing.T, mgr *container.Manager, host string, port int) bool {
	t.Helper()
	cmd := fmt.Sprintf("timeout 6 bash -c 'exec 3<>/dev/tcp/%s/%d'", host, port)
	_, err := mgr.ExecCommand(cmd, container.ExecCommandOptions{Capture: true})
	return err == nil
}

// containerCanResolve reports whether the container can resolve a DNS name via
// its normal resolver. Used to prove that DNS pinning leaves the bridge resolver
// (the container's default DHCP-provided DNS) working.
func containerCanResolve(t *testing.T, mgr *container.Manager, name string) bool {
	t.Helper()
	_, err := mgr.ExecCommand("timeout 6 getent hosts "+name, container.ExecCommandOptions{Capture: true})
	return err == nil
}

// launchE2EContainer launches a fresh container for an egress E2E test and
// registers cleanup. Returns the container manager and its IP.
func launchE2EContainer(t *testing.T, containerName string) (*container.Manager, string) {
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

	ip, err := GetContainerIP(containerName)
	if err != nil {
		t.Fatalf("get container IP: %v", err)
	}
	return mgr, ip
}

// TestE2E_RestrictedAllowedPorts_BlocksNonAllowedPort verifies, by real traffic,
// that allowed_ports in restricted mode lets an allowed destination port through
// and rejects a non-allowed one to the same host.
func TestE2E_RestrictedAllowedPorts_BlocksNonAllowedPort(t *testing.T) {
	skipUnlessAllowlistReady(t)

	const host = "1.1.1.1"
	const allowedPort = 443
	const blockedPort = 80

	mgr, containerIP := launchE2EContainer(t, "coi-e2e-restricted-ports")

	// Baseline (open network, before any Coi rules): both ports must be reachable,
	// or there is nothing meaningful to test — skip rather than false-pass.
	if !containerCanConnect(t, mgr, host, allowedPort) || !containerCanConnect(t, mgr, host, blockedPort) {
		t.Skipf("no baseline connectivity to %s:%d/%d — skipping", host, allowedPort, blockedPort)
	}

	netCfg := &config.NetworkConfig{
		Mode:         config.NetworkModeRestricted,
		AllowedPorts: []int{allowedPort},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())
	if err := netMgr.SetupForContainer(context.Background(), mgr.ContainerName); err != nil {
		t.Fatalf("SetupForContainer(restricted, allowed_ports): %v", err)
	}
	t.Cleanup(func() { _ = netMgr.Teardown(context.Background(), mgr.ContainerName) })

	if !containerCanConnect(t, mgr, host, allowedPort) {
		t.Errorf("expected %s:%d (allowed port) to remain reachable, but it was blocked", host, allowedPort)
	}
	if containerCanConnect(t, mgr, host, blockedPort) {
		t.Errorf("expected %s:%d (non-allowed port) to be BLOCKED, but the connection succeeded", host, blockedPort)
	}

	if err := netMgr.Teardown(context.Background(), mgr.ContainerName); err != nil {
		t.Errorf("Teardown: %v", err)
	}
	verifyTeardownRemovesRules(t, containerIP)

	// After teardown the blocked port is reachable again — proves the block was the
	// rule, not some incidental loss of connectivity.
	if !containerCanConnect(t, mgr, host, blockedPort) {
		t.Errorf("expected %s:%d reachable again after teardown, but it stayed blocked", host, blockedPort)
	}
}

// TestE2E_RestrictedDNSPin_BlocksUnpinnedResolver verifies, by real traffic, that
// dns_servers pins :53 to the listed resolver: the pinned resolver is reachable
// on 53, any other resolver is rejected on 53, and non-53 traffic to that other
// resolver is unaffected (the pin only touches port 53).
func TestE2E_RestrictedDNSPin_BlocksUnpinnedResolver(t *testing.T) {
	skipUnlessAllowlistReady(t)

	const pinned = "1.1.1.1" // the resolver we pin
	const other = "8.8.8.8"  // a different resolver, must be blocked on :53
	const dnsPort = 53
	const httpsPort = 443

	mgr, containerIP := launchE2EContainer(t, "coi-e2e-dns-pin")

	if !containerCanConnect(t, mgr, pinned, dnsPort) ||
		!containerCanConnect(t, mgr, other, dnsPort) ||
		!containerCanConnect(t, mgr, other, httpsPort) {
		t.Skipf("no baseline connectivity to the DNS/HTTPS targets — skipping")
	}
	// Capture baseline resolution BEFORE any rules, so we only assert "still
	// resolves" on a runner whose bridge DNS actually works to begin with.
	baselineResolves := containerCanResolve(t, mgr, "one.one.one.one")

	netCfg := &config.NetworkConfig{
		Mode:       config.NetworkModeRestricted,
		DNSServers: []string{pinned},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())
	if err := netMgr.SetupForContainer(context.Background(), mgr.ContainerName); err != nil {
		t.Fatalf("SetupForContainer(restricted, dns_servers): %v", err)
	}
	t.Cleanup(func() { _ = netMgr.Teardown(context.Background(), mgr.ContainerName) })

	if !containerCanConnect(t, mgr, pinned, dnsPort) {
		t.Errorf("expected pinned resolver %s:%d to be reachable, but it was blocked", pinned, dnsPort)
	}
	if containerCanConnect(t, mgr, other, dnsPort) {
		t.Errorf("expected unpinned resolver %s:%d to be BLOCKED, but the connection succeeded", other, dnsPort)
	}
	if !containerCanConnect(t, mgr, other, httpsPort) {
		t.Errorf("expected %s:%d (non-53) to be unaffected by the DNS pin, but it was blocked", other, httpsPort)
	}

	// The bridge resolver (the container's default DNS) must keep working — the pin
	// only touches the forward path. Only asserted when baseline resolution worked,
	// so a runner whose bridge has no upstream DNS doesn't false-fail.
	if baselineResolves && !containerCanResolve(t, mgr, "one.one.one.one") {
		t.Error("expected normal DNS resolution to keep working after pinning (bridge resolver must be untouched)")
	}

	if err := netMgr.Teardown(context.Background(), mgr.ContainerName); err != nil {
		t.Errorf("Teardown: %v", err)
	}
	verifyTeardownRemovesRules(t, containerIP)
}

// TestE2E_AllowlistAllowedPorts_ConstrainsAllowlistedHost verifies, by real
// traffic, that in allowlist mode allowed_ports constrains even an allowlisted
// host to the permitted ports, while a non-allowlisted host stays blocked
// entirely. The allowlist entry is a literal /32 so no DNS resolution is needed.
func TestE2E_AllowlistAllowedPorts_ConstrainsAllowlistedHost(t *testing.T) {
	skipUnlessAllowlistReady(t)

	const allowed = "1.1.1.1"    // allowlisted host
	const notAllowed = "8.8.8.8" // not in the allowlist
	const allowedPort = 443
	const blockedPort = 80

	mgr, containerIP := launchE2EContainer(t, "coi-e2e-allowlist-ports")

	if !containerCanConnect(t, mgr, allowed, allowedPort) ||
		!containerCanConnect(t, mgr, allowed, blockedPort) ||
		!containerCanConnect(t, mgr, notAllowed, allowedPort) {
		t.Skipf("no baseline connectivity to the allowlist E2E targets — skipping")
	}

	netCfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{allowed + "/32"},
		AllowedPorts:   []int{allowedPort},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())
	if err := netMgr.SetupForContainer(context.Background(), mgr.ContainerName); err != nil {
		t.Fatalf("SetupForContainer(allowlist, allowed_ports): %v", err)
	}
	t.Cleanup(func() { _ = netMgr.Teardown(context.Background(), mgr.ContainerName) })

	if !containerCanConnect(t, mgr, allowed, allowedPort) {
		t.Errorf("expected allowlisted %s:%d to be reachable, but it was blocked", allowed, allowedPort)
	}
	if containerCanConnect(t, mgr, allowed, blockedPort) {
		t.Errorf("expected allowlisted host %s on non-allowed port %d to be BLOCKED, but it succeeded", allowed, blockedPort)
	}
	if containerCanConnect(t, mgr, notAllowed, allowedPort) {
		t.Errorf("expected non-allowlisted %s:%d to be BLOCKED, but the connection succeeded", notAllowed, allowedPort)
	}

	if err := netMgr.Teardown(context.Background(), mgr.ContainerName); err != nil {
		t.Errorf("Teardown: %v", err)
	}
	verifyTeardownRemovesRules(t, containerIP)
}
