// Package network manages container network isolation: firewall rules for the
// restricted, open and allowlist modes, domain resolution and IP caching, and
// per-container /etc/hosts entries.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/logger"
)

// errNftNotAvailable is the user-facing error when nft is unavailable
const errNftNotAvailable = `nft is not available or passwordless sudo is not configured

Network isolation in restricted/allowlist modes requires nftables (nft).

To fix this:
  1. Install nftables: sudo apt install nftables
  2. Configure passwordless sudo for nft (validated with visudo):
     coi health --fix

Alternatively, run with unrestricted network access by setting open mode in
your config file (.coi/config.toml in your workspace, or the profile's
config.toml):

  [network]
  mode = "open"

If you have deliberately declined passwordless sudo (use_sudo = false), note
that restricted/allowlist modes cannot be enforced without it — use open mode.`

// Manager provides high-level network isolation management for containers
type Manager struct {
	config        *config.NetworkConfig
	nft           nftRuler
	resolver      *Resolver
	cacheManager  *CacheManager
	containerName string
	containerIP   string
	logger        *logger.SessionLogger

	// iptables fallback (when FORWARD DROP is set and bridge rules are missing)
	iptablesBridgeName string

	// Allowlist mode: the compiled policy. Its hostnames are resolved once and the
	// answers written to both the firewall and the container's /etc/hosts.
	policy *AllowPolicy

	// Refresher lifecycle (for allowlist mode)
	refreshCtx    context.Context
	refreshCancel context.CancelFunc
}

// NewManager creates a new network manager with the specified configuration
func NewManager(cfg *config.NetworkConfig, log *logger.SessionLogger) *Manager {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}

	// Route the package's resolver/nft diagnostics (which log via the package
	// logger, including from package-level helpers and the background refresher)
	// to this Manager's logger. This makes the caller's choice authoritative: a
	// discard logger (coi run / ConfigureContainer) actually silences network
	// output instead of falling back to stderr, and a session file logger keeps
	// it off the tmux terminal — issue #372. session.Setup also calls SetLogger
	// earlier to cover the pre-Manager boot rules; that is the same logger, so
	// the two stay consistent.
	SetLogger(log)

	return &Manager{
		config:       cfg,
		cacheManager: NewCacheManager(homeDir),
		logger:       log,
	}
}

// SetupForContainer configures network isolation for a container.
// It always removes the temporary boot-block rule installed by ApplyBootBlockRule
// once proper isolation rules are in place (or, for open mode, unconditionally —
// the user has opted into unrestricted access). On error in restricted/allowlist
// mode the boot block is intentionally left in place so the container stays
// blocked until the caller tears everything down.
func (m *Manager) SetupForContainer(ctx context.Context, containerName string) error {
	m.containerName = containerName

	// Handle different network modes
	switch m.config.Mode {
	case config.NetworkModeOpen:
		m.logger.Println("Network mode: open (no restrictions)")
		// Add ACCEPT rules via nft so traffic flows even when FORWARD policy is DROP
		if NftUsable(m.config) {
			containerIP, err := GetContainerIP(containerName)
			if err != nil {
				m.logger.Errorf("Warning: could not get container IP for open mode rules: %v", err)
			} else {
				m.containerIP = containerIP
				m.nft = NewNftManager(containerIP, "")
				m.purgeStaleRulesForIP(containerIP)
				if err := EnsureOpenModeRules(containerIP); err != nil {
					m.logger.Errorf("Warning: could not add open mode rules: %v", err)
				}
			}
		} else if m.config.SudoAllowed() && NeedsIptablesFallback() {
			bridgeName, err := GetIncusBridgeName()
			if err != nil {
				m.logger.Errorf("Warning: could not get bridge name for iptables fallback: %v", err)
			} else {
				if err := EnsureIptablesBridgeRules(bridgeName); err != nil {
					m.logger.Errorf("Warning: could not add iptables bridge rules: %v", err)
				} else {
					m.iptablesBridgeName = bridgeName
					m.logger.Printf("iptables fallback: added FORWARD ACCEPT rules for bridge %s (FORWARD policy is DROP, nft not available)", bridgeName)
				}
			}
		}
		// Open mode always lifts the boot block — errors above are non-fatal
		// and the user has explicitly opted into unrestricted network access.
		if err := m.applyUserHosts(containerName); err != nil {
			return err
		}
		m.removeBootBlock(containerName)
		return nil

	case config.NetworkModeRestricted:
		if err := m.setupRestricted(ctx, containerName); err != nil {
			return err // boot block stays: container remains isolated on error
		}

	case config.NetworkModeAllowlist:
		if err := m.setupAllowlist(ctx, containerName); err != nil {
			return err // boot block stays: container remains isolated on error
		}

	default:
		return fmt.Errorf("unknown network mode: %s", m.config.Mode)
	}

	// Restricted or allowlist rules are now in place — lift the boot block.
	if err := m.applyUserHosts(containerName); err != nil {
		return err
	}
	m.removeBootBlock(containerName)
	return nil
}

// applyUserHosts writes the configured [[network.hosts]] entries into the
// container's /etc/hosts and makes them reachable under the active mode. Fatal on
// failure and run BEFORE the boot block is lifted, so a bad host entry fails the
// session closed rather than leaving a dead name or half-applied firewall rule.
func (m *Manager) applyUserHosts(containerName string) error {
	if len(m.config.Hosts) == 0 {
		return nil
	}
	if err := ApplyUserHosts(containerName, m.config.Mode, config.BoolVal(m.config.AllowLocalNetworkAccess), m.config.Hosts, m.config.AllowedPorts); err != nil {
		return fmt.Errorf("failed to apply [[network.hosts]]: %w", err)
	}
	m.logger.Printf("Applied %d configured host entr(y/ies) to /etc/hosts", len(m.config.Hosts))
	return nil
}

// removeBootBlock removes the temporary boot-block nft rule for containerName,
// logging a warning if removal fails (non-fatal).
func (m *Manager) removeBootBlock(containerName string) {
	if err := RemoveBootBlockRule(containerName); err != nil {
		m.logger.Errorf("Warning: failed to remove boot block rule for %s: %v", containerName, err)
	}
}

// purgeStaleRulesForIP removes any coi-<IP> rules left in the forward chain by a
// previous container that held this IP. Incus DHCP recycles leases, so a new
// container frequently reuses a prior one's address; if that prior container did
// not tear down cleanly (kill -9, OOM, host crash, or a teardown that could not
// resolve the already-deleted container's IP), its IP-keyed rules are orphaned.
// Because the forward chain is evaluated first-match-wins, an inherited blanket
// ACCEPT would let a restricted/allowlist successor bypass its filter entirely.
// Reset-then-apply: purge the IP's rules before installing this container's
// policy. Best-effort — deleteNFTRulesByComment retries internally and the rule
// comment is matched exactly, so coi-base and coi-boot-<name> are never touched.
func (m *Manager) purgeStaleRulesForIP(containerIP string) {
	if containerIP == "" {
		return
	}
	if err := DeleteCOIFilterRulesForIP(containerIP); err != nil {
		m.logger.Errorf("Warning: failed to purge stale nft rules for %s: %v", containerIP, err)
	}
}

// setupRestricted configures restricted mode using nftables
func (m *Manager) setupRestricted(ctx context.Context, containerName string) error {
	m.logger.Println("Network mode: restricted (blocking local/internal networks)")

	// Check if nft is available (and that sudo is permitted by config)
	if !NftUsable(m.config) {
		return fmt.Errorf("%s", errNftNotAvailable)
	}

	// Get container IP
	containerIP, err := GetContainerIP(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container IP: %w", err)
	}
	m.containerIP = containerIP
	m.logger.Printf("Container IP: %s", containerIP)

	// Get gateway IP
	gatewayIP, err := getContainerGatewayIP(containerName)
	if err != nil {
		m.logger.Errorf("Warning: Could not auto-detect gateway IP: %v", err)
	} else {
		m.logger.Printf("Gateway IP: %s", gatewayIP)
	}

	// Disable IPv6 inside the container (defence-in-depth; reversible by
	// in-container root, so the host-side drop below is the enforced boundary).
	if err := DisableIPv6ForContainer(containerName); err != nil {
		m.logger.Errorf("Warning: failed to disable IPv6 in container: %v", err)
	}

	// Enforce the IPv6 egress boundary on the host: drop all forwarded IPv6 from
	// the container's veth. The Coi filter table is IPv4-only, so without this an
	// agent that re-enables IPv6 escapes the firewall entirely. Fail closed — if
	// the drop cannot be installed the boot block stays in place and setup aborts.
	if err := ApplyIPv6BlockForContainer(containerName); err != nil {
		return fmt.Errorf("failed to enforce IPv6 egress block: %w", err)
	}

	// Create nft manager
	m.nft = NewNftManager(containerIP, gatewayIP)
	m.purgeStaleRulesForIP(containerIP)

	// Apply restricted mode rules
	if err := m.nft.ApplyRestricted(m.config); err != nil {
		return fmt.Errorf("failed to apply nft rules: %w", err)
	}

	m.logger.Printf("nft rules applied for container %s", containerName)

	// Log what is blocked
	if config.BoolVal(m.config.BlockPrivateNetworks) {
		m.logger.Println("  Blocking private networks (RFC1918)")
	}
	if config.BoolVal(m.config.BlockMetadataEndpoint) {
		m.logger.Println("  Blocking cloud metadata endpoints")
	}

	return nil
}

// setupAllowlist configures allowlist mode.
//
// Name resolution is made deterministic instead of live: Coi resolves the
// allowed hostnames on the host, installs those addresses in the container's nft
// set, writes the SAME addresses into the container's /etc/hosts (see hosts.go),
// and blocks all DNS egress (see dnsblock.go). With no route to a nameserver, the
// hosts file Coi wrote is the container's only way to turn a name into an address
// — so it cannot learn about an address the firewall does not already trust, and
// the host/container divergence this mode exists to prevent has nowhere to occur.
//
// Nothing has to stay running for that to hold, which is what makes it survive
// coi exiting, a tmux detach, or a kill -9.
//
// Literal IP/CIDR entries in allowed_domains skip DNS entirely and go straight
// into the static set.
func (m *Manager) setupAllowlist(ctx context.Context, containerName string) error {
	m.logger.Println("Network mode: allowlist (deterministic name resolution, DNS blocked)")

	// Check if nft is available (and that sudo is permitted by config)
	if !NftUsable(m.config) {
		return fmt.Errorf("%s", errNftNotAvailable)
	}

	// Validate configuration
	if len(m.config.AllowedDomains) == 0 {
		return fmt.Errorf("allowlist mode requires at least one allowed domain")
	}

	// dns_servers is meaningless — and actively harmful — in allowlist mode, which
	// deliberately blocks ALL DNS and makes the container's /etc/hosts the single
	// source of name resolution. Re-opening :53 to a pinned resolver would let the
	// container learn addresses the firewall was never told about, the exact
	// host/container divergence this mode exists to prevent. Fail loudly rather
	// than silently ignore a security-shaped setting.
	if len(m.config.DNSServers) > 0 {
		return fmt.Errorf("network.dns_servers is not compatible with allowlist mode: " +
			"allowlist mode blocks all DNS and resolves names via /etc/hosts. " +
			"Use dns_servers with restricted mode, or list the resolver in allowed_domains")
	}

	policy, err := NewAllowPolicy(m.config.AllowedDomains)
	if err != nil {
		return fmt.Errorf("invalid allowed_domains: %w", err)
	}
	m.policy = policy

	// Get container IP
	containerIP, err := GetContainerIP(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container IP: %w", err)
	}
	m.containerIP = containerIP
	m.logger.Printf("Container IP: %s", containerIP)

	// The gateway address keys the DHCP accept rule (the lease is what gives the
	// container the IP every other rule is keyed on), so allowlist mode cannot
	// proceed without it. Failing here is fail-closed: the boot block stays in
	// place and the container has no egress at all.
	gatewayIP, err := getContainerGatewayIP(containerName)
	if err != nil {
		return fmt.Errorf("failed to determine gateway IP (required for allowlist mode): %w", err)
	}
	m.logger.Printf("Gateway IP: %s", gatewayIP)

	// Disable IPv6 inside the container (defence-in-depth; reversible by
	// in-container root, so the host-side drop below is the enforced boundary).
	if err := DisableIPv6ForContainer(containerName); err != nil {
		m.logger.Errorf("Warning: failed to disable IPv6 in container: %v", err)
	}

	// Enforce the IPv6 egress boundary on the host: drop all forwarded IPv6 from
	// the container's veth. The Coi filter table is IPv4-only, so without this an
	// agent that re-enables IPv6 escapes the allowlist entirely. Fail closed — if
	// the drop cannot be installed the boot block stays in place and setup aborts.
	if err := ApplyIPv6BlockForContainer(containerName); err != nil {
		return fmt.Errorf("failed to enforce IPv6 egress block: %w", err)
	}

	// Create nft manager
	m.nft = NewNftManager(containerIP, gatewayIP)
	m.purgeStaleRulesForIP(containerIP)

	// Install the rules and the static (literal IP/CIDR) entries. The rules name
	// the container's sets, not individual addresses, so they are stable for the
	// life of the container. This also blocks all DNS egress — which is what makes
	// the hosts file written below the container's only source of addresses.
	staticCIDRs := policy.StaticCIDRs()
	if err := m.nft.ApplyAllowlist(m.config, staticCIDRs); err != nil {
		return fmt.Errorf("failed to apply nft rules: %w", err)
	}
	m.logger.Printf("nft rules applied for container %s (%d literal address entries, %d hostnames)",
		containerName, len(staticCIDRs), len(policy.Names()))

	// Resolve the configured hostnames and install the answers on BOTH sides: the
	// firewall set and the container's /etc/hosts. Fatal on failure — a container
	// that cannot resolve its allowlisted domains has no working network, and
	// saying so now beats a session that mysteriously cannot reach anything.
	if err := m.installNames(containerName); err != nil {
		return err
	}

	m.logger.Println("  Allowing only allowlisted destinations")
	m.logger.Println("  DNS blocked: /etc/hosts is the container's only name resolution")
	m.logger.Println("  Blocking all RFC1918 private networks")
	m.logger.Println("  Blocking cloud metadata endpoints")

	// Re-resolve periodically so the addresses do not drift too far from DNS. The
	// firewall and the hosts file are updated together, so they can never disagree
	// — and if this refresher dies with the coi process, both simply stop moving in
	// lockstep, which still leaves a container that works.
	m.startRefresher(ctx, m.resolver.GetMinTTL())

	return nil
}

// installNames resolves the policy's hostnames and writes the result to the two
// places that must agree: the container's nft set and its /etc/hosts.
//
// Order matters. The firewall is updated FIRST, so there is never a moment where
// the container can resolve a name to an address the firewall has not yet been
// told about. The reverse order would open exactly the window this design exists
// to close, just a much smaller one.
func (m *Manager) installNames(containerName string) error {
	names := m.policy.Names()

	cache, err := m.cacheManager.Load(containerName)
	if err != nil {
		m.logger.Errorf("Warning: Failed to load cache: %v", err)
		cache = &IPCache{
			Domains:    make(map[string][]string),
			TTLs:       make(map[string]uint32),
			LastUpdate: time.Time{},
		}
	}
	m.resolver = NewResolver(cache)

	if len(names) == 0 {
		// An address-only allowlist is legitimate: the container reaches the
		// configured IPs directly and needs no names at all.
		return nil
	}

	m.logger.Printf("Resolving %d allowlisted hostnames...", len(names))
	domainIPs, err := m.resolver.ResolveAll(names)
	if err != nil && len(domainIPs) == 0 {
		return fmt.Errorf("failed to resolve any allowlisted hostname: %w", err)
	}

	if err := m.syncResolved(domainIPs); err != nil {
		return err
	}

	m.resolver.UpdateCache(domainIPs)
	if err := m.cacheManager.Save(containerName, m.resolver.GetCache()); err != nil {
		m.logger.Errorf("Warning: Failed to save cache: %v", err)
	}
	return nil
}

// syncResolved installs resolved addresses into the firewall and then into the
// container's /etc/hosts, keeping the two in lockstep. Firewall first — see
// installNames.
func (m *Manager) syncResolved(domainIPs map[string][]string) error {
	allower := m.nftSetAllower()
	refreshInterval := m.dynamicElementLifetimeInterval()
	// The global allowed_ports a name inherits when it named no port of its own.
	// Already validated at ApplyAllowlist (setup fails closed before we get here),
	// so a plain conversion is safe.
	globalPorts := intsToPortRanges(m.config.AllowedPorts)
	for domain, ips := range domainIPs {
		if len(ips) == 0 {
			continue
		}
		ttl := m.resolver.DomainTTLs[domain]
		var entryPorts []portRange
		if m.policy != nil {
			entryPorts = m.policy.portsForName(domain)
		}
		ports := resolvePorts(entryPorts, globalPorts)
		if err := allower.AllowDynamicIPsPorts(ips, ports, ttl, refreshInterval); err != nil {
			return fmt.Errorf("failed to allow %d addresses for %s: %w", len(ips), domain, err)
		}
		m.logger.Printf("  %s -> %v", domain, ips)
	}

	if m.containerName == "" {
		return nil // no container to write to (unit tests)
	}
	if err := WriteAllowlistHosts(m.containerName, domainIPs); err != nil {
		return fmt.Errorf("failed to write the container's hosts entries: %w", err)
	}
	return nil
}

// nftSetAllower exposes the nft manager's set writer. Falls back to a no-op when
// the nft layer is a test stub that cannot install elements.
func (m *Manager) nftSetAllower() dynAllower {
	if a, ok := m.nft.(dynAllower); ok {
		return a
	}
	return noopAllower{}
}

// dynamicElementLifetimeInterval reports the kernel timeout to give DNS-learned
// set elements. It is always 0 (permanent).
//
// A finite kernel timeout only stays safe if something re-adds the element before
// it expires, and the only thing that would is the in-process refresher goroutine
// — which cannot be relied on to outlive the container. `coi shell --background`
// returns within seconds (and its deferred Teardown cancels the refresher);
// detaching from tmux exits the process too. In both — the deployments the design
// advertises as surviving a `coi` exit — the container keeps running with no
// refresher, so a finite timeout would silently evict a still-valid address after
// TTL+interval+grace (~20 min by default, 12 h cap) and the container would then
// resolve an allowlisted name from /etc/hosts to an address the firewall no longer
// holds, hit the default reject, and die mid-task with "Unable to connect" — the
// exact failure this whole mode exists to prevent, now non-self-healing. This is
// precisely the reasoning that removed the in-process DNS proxy (the container
// outlives the coi process); it applies identically to the refresher.
//
// Permanent elements make the set survive a `coi` exit for the addresses the
// container was actually handed (frozen /etc/hosts ⊆ permanent set — always
// consistent, never a fresh-but-divergent state). The refresher, while it is
// alive, still adds newly-rotated pool members and syncs /etc/hosts; it just no
// longer bears the burden of keeping existing elements from expiring.
//
// Tradeoff: the set is no longer auto-pruned by kernel timeout, so it grows with
// every rotated address over a very long session. Bounded in practice (an
// ephemeral container's lifetime, a bounded frontend pool, and nft handles many
// thousands of elements), but the proper way to bound it is refresher-driven
// pruning of addresses that have dropped out of DNS — a follow-up, since eviction
// must never race an in-flight connection and needs its own grace window.
func (m *Manager) dynamicElementLifetimeInterval() time.Duration {
	return 0 // permanent: the refresher cannot outlive the container, so nothing can renew a finite timeout
}

// noopAllower stands in when the nft layer cannot install set elements (tests).
type noopAllower struct{}

// AllowDynamicIPsPorts discards the elements and always succeeds.
func (noopAllower) AllowDynamicIPsPorts([]string, []portRange, uint32, time.Duration) error {
	return nil
}

// computeRefreshInterval determines the refresh interval based on DNS TTL and config cap.
// The configured refresh_interval_minutes acts as a maximum cap.
// If minTTL is 0 (unknown), the config interval is used as-is.
func (m *Manager) computeRefreshInterval(minTTL uint32) time.Duration {
	configInterval := time.Duration(m.config.RefreshIntervalMinutes) * time.Minute

	if minTTL == 0 {
		return configInterval
	}

	ttlInterval := time.Duration(minTTL) * time.Second

	if ttlInterval < configInterval {
		return ttlInterval
	}

	return configInterval
}

// startRefresher starts the background IP refresh goroutine with TTL-aware scheduling.
// It uses time.Timer instead of time.Ticker to allow dynamic rescheduling after each refresh.
func (m *Manager) startRefresher(ctx context.Context, initialMinTTL uint32) {
	if m.config.RefreshIntervalMinutes <= 0 {
		m.logger.Println("IP refresh disabled (refresh_interval_minutes <= 0)")
		return
	}

	m.refreshCtx, m.refreshCancel = context.WithCancel(ctx)

	interval := m.computeRefreshInterval(initialMinTTL)
	timer := time.NewTimer(interval)

	m.logger.Printf("Starting IP refresh (interval: %s, TTL-based: %v)", interval, initialMinTTL > 0)

	go func() {
		defer timer.Stop()

		for {
			select {
			case <-timer.C:
				m.logger.Println("IP refresh: checking for updated IPs...")
				newMinTTL, err := m.refreshAllowedIPs()
				if err != nil {
					m.logger.Errorf("Warning: IP refresh failed: %v", err)
				}

				// Recompute interval from new TTLs
				nextInterval := m.computeRefreshInterval(newMinTTL)
				m.logger.Printf("IP refresh: next check in %s", nextInterval)
				timer.Reset(nextInterval)

			case <-m.refreshCtx.Done():
				m.logger.Println("IP refresher stopped")
				return
			}
		}
	}()
}

// stopRefresher stops the background refresher goroutine
func (m *Manager) stopRefresher() {
	if m.refreshCancel != nil {
		m.refreshCancel()
		m.refreshCancel = nil
	}
}

// refreshAllowedIPs re-resolves the policy's hostnames and re-installs the
// answers into both the firewall and the container's /etc/hosts. Returns the
// minimum TTL for rescheduling.
//
// This keeps the container's addresses from drifting too far from DNS over a long
// session. It is not load-bearing: the firewall and the hosts file are written
// together and therefore always agree, so if this refresher dies with the coi
// process the container is left with addresses that are merely stale — and a
// stale-but-consistent address still connects. It was fresh-but-divergent that
// broke, which is the state this design can no longer reach.
func (m *Manager) refreshAllowedIPs() (uint32, error) {
	if m.policy == nil || m.resolver == nil {
		return 0, nil
	}
	names := m.policy.Names()
	if len(names) == 0 {
		return 0, nil
	}

	newIPs, err := m.resolver.ResolveAll(names)
	if err != nil && len(newIPs) == 0 {
		return 0, fmt.Errorf("failed to resolve any domains")
	}

	if err := m.syncResolved(newIPs); err != nil {
		return 0, err
	}

	m.resolver.UpdateCache(newIPs)
	if err := m.cacheManager.Save(m.containerName, m.resolver.GetCache()); err != nil {
		m.logger.Errorf("Warning: Failed to save cache: %v", err)
	}

	return m.resolver.GetMinTTL(), nil
}

// Teardown removes network isolation for a container
func (m *Manager) Teardown(ctx context.Context, containerName string) error {
	// Stop background refresher if running (for allowlist mode)
	m.stopRefresher()

	// Clean up iptables bridge rules if we added them
	if m.iptablesBridgeName != "" {
		// Check if other coi containers are still running before removing
		output, err := container.IncusOutput("list", "--format=json")
		hasOtherContainers := true // conservative default
		if err == nil {
			hasOtherContainers = otherContainersRunning(output, containerName)
		}

		if !hasOtherContainers {
			if err := RemoveIptablesBridgeRules(m.iptablesBridgeName); err != nil {
				m.logger.Errorf("Warning: failed to remove iptables bridge rules: %v", err)
			} else {
				m.logger.Printf("iptables fallback: removed FORWARD ACCEPT rules for bridge %s", m.iptablesBridgeName)
			}
		} else {
			m.logger.Printf("iptables fallback: skipping rule removal, other containers still running")
		}
	}

	// For open mode, also clean up nft ACCEPT rules created by EnsureOpenModeRules()
	if m.config.Mode == config.NetworkModeOpen {
		if !NftUsable(m.config) && m.iptablesBridgeName == "" {
			return nil // No nft and no iptables fallback, no rules to clean up
		}

		// Use cached container IP if available (set during SetupForContainer)
		// Only try to get from container if not cached
		if m.containerIP == "" {
			containerIP, err := GetContainerIP(containerName)
			if err != nil {
				return nil // Container might be already deleted, and IP wasn't cached
			}
			m.containerIP = containerIP
		}

		// Create nft manager if not already created
		if m.nft == nil {
			m.nft = NewNftManager(m.containerIP, "")
		}
	}

	// Remove nft rules for ALL modes
	if m.nft != nil {
		if err := m.nft.RemoveRules(); err != nil {
			m.logger.Errorf("Warning: failed to remove nft rules: %v", err)
		} else {
			m.logger.Printf("nft rules removed for container %s", containerName)
		}
	}

	// Remove the host-side IPv6 egress block (idempotent — only present for
	// restricted/allowlist modes, but safe to call for all modes).
	if err := RemoveIPv6BlockForContainer(containerName); err != nil {
		m.logger.Errorf("Warning: failed to remove IPv6 block rule for %s: %v", containerName, err)
	}

	// Clean up any residual boot-block rule (idempotent — no-op if already removed
	// by SetupForContainer, but handles the case where setup failed mid-way).
	m.removeBootBlock(containerName)

	return nil
}

// GetMode returns the current network mode
func (m *Manager) GetMode() config.NetworkMode {
	return m.config.Mode
}

// GetContainerGatewayIP exports the gateway IP detection for external use
func GetContainerGatewayIP(containerName string) (string, error) {
	return getContainerGatewayIP(containerName)
}

// getContainerGatewayIP auto-detects the gateway IP for a container's network
func getContainerGatewayIP(containerName string) (string, error) {
	networkName, err := GetIncusBridgeName()
	if err != nil {
		return "", err
	}

	// Get network configuration
	networkOutput, err := container.IncusOutput("network", "show", networkName)
	if err != nil {
		return "", fmt.Errorf("failed to get network info: %w", err)
	}

	// Parse gateway IP (ipv4.address field)
	for _, line := range strings.Split(networkOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ipv4.address:") {
			addressWithMask := strings.TrimSpace(strings.TrimPrefix(line, "ipv4.address:"))
			// Remove CIDR suffix (e.g., "10.128.178.1/24" -> "10.128.178.1")
			gatewayIP := addressWithMask
			if idx := strings.Index(addressWithMask, "/"); idx != -1 {
				gatewayIP = addressWithMask[:idx]
			}

			// Validate that we extracted a valid IPv4 address
			if net.ParseIP(gatewayIP) == nil {
				return "", fmt.Errorf("invalid IPv4 address extracted: %s", gatewayIP)
			}

			return gatewayIP, nil
		}
	}

	return "", fmt.Errorf("could not find ipv4.address in network %s", networkName)
}

// otherContainersRunning parses the JSON output of `incus list --format=json`
// and reports whether any container other than excludeName is currently Running.
// On JSON parse failure it returns true (conservative: keep bridge rules).
func otherContainersRunning(jsonOutput, excludeName string) bool {
	var containers []struct {
		Name  string `json:"name"`
		State struct {
			Status string `json:"status"`
		} `json:"state"`
	}
	if err := json.Unmarshal([]byte(jsonOutput), &containers); err != nil {
		return true // conservative: can't confirm no other containers, keep rules
	}
	for _, c := range containers {
		if c.Name != excludeName && container.StatusIsRunning(c.State.Status) {
			return true
		}
	}
	return false
}
