package network

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// NftManager manages nftables rules for container network isolation.
// Rules live in the dedicated "ip coi" table, forward chain, keeping Coi
// rules isolated from Docker, ufw, and other tools.
type NftManager struct {
	containerIP string
	gatewayIP   string

	// dynSeen tracks the DNS-learned addresses already installed in the dynamic
	// address set, and dynSeenTuples the (address . port) elements in the dynamic
	// port-scoped set, with each element's expiry, so AllowDynamicIPsPorts can skip
	// the nft exec when an element is still fresh. Both are guarded by dynMu so a
	// re-sync from the background refresher cannot race a concurrent caller — see
	// AllowDynamicIPsPorts.
	dynMu         sync.Mutex
	dynSeen       map[string]time.Time
	dynSeenTuples map[string]time.Time

	// batch, when non-nil, collects the rule adds of ApplyRestricted /
	// ApplyAllowlist so they apply as ONE nft transaction (see runNFTScript)
	// instead of one sudo+nft exec per rule. Setup-only: the background
	// refresher never adds rules, it only touches set elements.
	batch [][]string
}

// beginBatch starts collecting rule adds. prefix commands (e.g. deletes of a
// previous session's rules for this IP) run first in the same transaction, so
// replacing a container's rules never passes through a moment with neither
// the old nor the new rules in place.
func (f *NftManager) beginBatch(prefix [][]string) {
	f.batch = append([][]string{}, prefix...)
}

// commitBatch applies the collected commands in one transaction and stops
// batching. On failure nothing was applied (nft transactions are atomic).
func (f *NftManager) commitBatch() error {
	cmds := f.batch
	f.batch = nil
	return runNFTScript(cmds)
}

// abortBatch drops the collected commands without applying them.
func (f *NftManager) abortBatch() { f.batch = nil }

// NewNftManager creates a new nft manager for a container
func NewNftManager(containerIP, gatewayIP string) *NftManager {
	return &NftManager{
		containerIP: containerIP,
		gatewayIP:   gatewayIP,
		dynSeen:     make(map[string]time.Time),
	}
}

// ApplyRestricted applies restricted mode rules (block RFC1918, allow internet).
//
// Two optional egress controls layer on top of the classic behaviour, each a
// no-op when unset so existing configs emit byte-identical rules:
//
//   - dns_servers: pin the resolvers reachable on port 53 (see pinDNSForward).
//   - allowed_ports: cap the otherwise-open internet egress to specific dports.
func (f *NftManager) ApplyRestricted(cfg *config.NetworkConfig) error {
	return f.applyRestricted(cfg, nil)
}

// applyRestricted is ApplyRestricted with prefix commands (stale-rule deletes)
// applied in the same transaction as the new rules.
func (f *NftManager) applyRestricted(cfg *config.NetworkConfig, prefix [][]string) error {
	// Validate the optional egress controls up front. Setup is fail-closed, so a
	// bad dns_servers/allowed_ports value aborts here with the boot block still in
	// place rather than installing a half-applied policy.
	dnsServers, err := validateDNSServers(cfg.DNSServers)
	if err != nil {
		return err
	}
	allowedPorts, err := validateAllowedPorts(cfg.AllowedPorts)
	if err != nil {
		return err
	}

	if err := EnsureBaseRules(); err != nil {
		logWarnf("Warning: failed to ensure base rules: %v", err)
	}

	// Every rule below is collected and applied as one transaction (together
	// with the prefix deletes): all of the policy or none of it.
	f.beginBatch(prefix)
	if err := f.addRestrictedRules(cfg, dnsServers, allowedPorts); err != nil {
		f.abortBatch()
		return err
	}
	if err := f.commitBatch(); err != nil {
		return fmt.Errorf("failed to apply restricted rules: %w", err)
	}
	return nil
}

// addRestrictedRules emits restricted mode's rules, in order.
func (f *NftManager) addRestrictedRules(cfg *config.NetworkConfig, dnsServers []string, allowedPorts []int) error {
	if f.gatewayIP != "" {
		if err := f.addRule(f.containerIP, f.gatewayIP+"/32", "accept"); err != nil {
			return fmt.Errorf("failed to add gateway allow rule: %w", err)
		}
	}

	// DNS pinning must precede the RFC1918 block so a pinned LAN resolver stays
	// reachable on 53, and must precede the permissive default so a pinned public
	// resolver is accepted before the port cap / catch-all could touch it.
	if err := f.pinDNSForward(dnsServers); err != nil {
		return err
	}

	if config.BoolVal(cfg.AllowLocalNetworkAccess) {
		// allowed_ports still applies to the LAN (see addLocalNetworkAllows): local
		// access opens the LAN, but only on the permitted ports when a cap is set.
		if err := f.addLocalNetworkAllows(allowedPorts); err != nil {
			return err
		}
	} else if config.BoolVal(cfg.BlockPrivateNetworks) {
		for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
			if err := f.addRule(f.containerIP, cidr, "reject"); err != nil {
				return fmt.Errorf("failed to add RFC1918 block rule: %w", err)
			}
		}
	}

	if config.BoolVal(cfg.BlockMetadataEndpoint) {
		if err := f.addRule(f.containerIP, "169.254.0.0/16", "reject"); err != nil {
			return fmt.Errorf("failed to add metadata block rule: %w", err)
		}
	}

	// Allow remaining internet traffic (needed when FORWARD policy is DROP). With
	// allowed_ports set this becomes a port-capped accept plus a default reject,
	// turning restricted mode from allow-by-default into "internet, but only on
	// these ports"; ICMP echo stays permitted so ping/health checks still work.
	// Without allowed_ports it is the historic blanket accept.
	if len(allowedPorts) > 0 {
		if err := f.addRuleWithMatch(f.containerIP, "0.0.0.0/0", l4PortMatch(allowedPorts), "accept"); err != nil {
			return fmt.Errorf("failed to add port-capped allow rule: %w", err)
		}
		if err := f.addRuleWithMatch(f.containerIP, "0.0.0.0/0",
			[]string{"icmp", "type", "echo-request", "limit", "rate", "10/second"}, "accept"); err != nil {
			return fmt.Errorf("failed to add ICMP allow rule: %w", err)
		}
		if err := f.addRule(f.containerIP, "0.0.0.0/0", "reject"); err != nil {
			return fmt.Errorf("failed to add port-cap default deny rule: %w", err)
		}
	} else if err := f.addRule(f.containerIP, "0.0.0.0/0", "accept"); err != nil {
		return fmt.Errorf("failed to add default allow rule: %w", err)
	}

	return nil
}

// ApplyAllowlist applies allowlist mode rules: block all DNS, accept traffic to
// the container's allowlist sets, reject everything else.
//
// The rules installed here are fixed for the life of the container — they name
// the sets, not the addresses. Everything that varies (a domain's addresses
// rotating out of DNS) is an element operation on a set, applied atomically by
// the kernel. See nftset.go.
//
// The literal IP/CIDR entries come from allowed_domains. Resolved name entries
// land in the dynamic set, and the same addresses are written into the container's
// /etc/hosts (see hosts.go) — which, with DNS blocked, is the container's only
// route from a name to an address.
//
// The compiled policy is the SINGLE source for both the address set (ICMP + the
// security monitor) and the port-scoped set (L4), so the two cannot diverge. The
// second parameter is retained for the nftRuler interface; the addresses it would
// carry are exactly policy.StaticCIDRs(), which we derive here instead.
//
// A gateway IP is mandatory: allowlist mode is default-reject, so DHCP lease
// renewal has to be explicitly allowed or the lease eventually lapses and the
// container loses the IP every rule here is keyed on. setupAllowlist already
// fails closed when the gateway cannot be detected; this guard states the same
// requirement at the point that consumes it.
func (f *NftManager) ApplyAllowlist(cfg *config.NetworkConfig, _ []string) error {
	if f.gatewayIP == "" {
		return fmt.Errorf("allowlist mode requires a gateway IP (for the DHCP renewal accept rule)")
	}

	// allowed_ports optionally caps which dports the allowlisted hosts are reachable
	// on. Validated up front so setup fails closed on a bad value. (dns_servers is
	// rejected earlier, in setupAllowlist: allowlist mode blocks all DNS by design.)
	allowedPorts, err := validateAllowedPorts(cfg.AllowedPorts)
	if err != nil {
		return err
	}
	// Compile the allowlist once — both sets are built from it, so the address set
	// and the port-scoped set share one source of truth.
	policy, err := NewAllowPolicy(cfg.AllowedDomains)
	if err != nil {
		return fmt.Errorf("failed to compile allowed_domains: %w", err)
	}

	if err := EnsureBaseRules(); err != nil {
		logWarnf("Warning: failed to ensure base rules: %v", err)
	}

	if err := f.ensureAllowlistSets(); err != nil {
		return err
	}
	if err := f.AddStaticIPs(policy.StaticCIDRs()); err != nil {
		return err
	}
	if err := f.AddStaticTuples(policy.staticTuples(), intsToPortRanges(allowedPorts)); err != nil {
		return err
	}

	// Block DNS before anything else is allowed. This is what makes the hosts file
	// authoritative: with no way to query a nameserver, the container cannot learn
	// an address the firewall has not already been told about, and the host/container
	// divergence that this whole mode exists to prevent has nowhere to occur.
	//
	// It has to be done in TWO chains. Traffic to an off-box resolver (8.8.8.8) is
	// forwarded, so the forward chain catches it — and it must be rejected BEFORE
	// the set rules, or a resolver that happens to sit inside an allowlisted CIDR
	// would be reachable on port 53 and could hand the container any address it
	// liked. Traffic to the bridge's own resolver is addressed to the host, so it
	// never traverses the forward chain at all; only an input rule can stop it.
	if err := f.blockDNS(); err != nil {
		return err
	}

	// The remaining rules are collected and applied as ONE transaction, after
	// the DNS block above is already in place (so ordering is unchanged): all
	// of them apply, or none do and the boot block keeps the container dark.
	f.beginBatch(nil)
	if err := f.addAllowlistRules(cfg, allowedPorts); err != nil {
		f.abortBatch()
		return err
	}
	if err := f.commitBatch(); err != nil {
		return fmt.Errorf("failed to apply allowlist rules: %w", err)
	}
	return nil
}

// addAllowlistRules emits allowlist mode's forward rules after the DNS block,
// in order.
func (f *NftManager) addAllowlistRules(cfg *config.NetworkConfig, allowedPorts []int) error {
	// DHCP still has to work. The lease is what gives the container the address
	// every one of these rules is keyed on. The gateway is guaranteed present by
	// the guard above, so this rule is unconditional.
	if err := f.addRuleWithMatch(f.containerIP, f.gatewayIP+"/32",
		[]string{"udp", "dport", "{", "67,", "68", "}"}, "accept"); err != nil {
		return fmt.Errorf("failed to add gateway DHCP allow rule: %w", err)
	}

	// Private-network / link-local handling MUST precede the set-accept rules
	// below. A resolved DNS answer — or a literal allowed_domains entry — that
	// lands in a private or link-local range would otherwise be matched by the
	// set-accept rule before any reject runs, opening a DNS-rebinding path to
	// 169.254.169.254 (cloud metadata → credential theft) or to internal hosts.
	// (Restricted mode already rejects these ahead of its permissive default;
	// allowlist mode was rejecting them AFTER its set-accepts, so any set member
	// in these ranges slipped straight through.) Semantics are unchanged from the
	// previous placement — only the order is fixed.
	//
	// NB: this still keys off allow_local_network_access alone, as the previous
	// code did; wiring allowlist mode to honor block_private_networks /
	// block_metadata_endpoint independently (as restricted mode does) — and thus
	// blocking metadata even when local access is on — is a separate follow-up.
	if config.BoolVal(cfg.AllowLocalNetworkAccess) {
		// allowed_ports still applies to the LAN (see addLocalNetworkAllows): local
		// access opens the LAN, but only on the permitted ports when a cap is set.
		if err := f.addLocalNetworkAllows(allowedPorts); err != nil {
			return err
		}
	} else {
		for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"} {
			if err := f.addRule(f.containerIP, cidr, "reject"); err != nil {
				return fmt.Errorf("failed to add RFC1918/metadata block rule: %w", err)
			}
		}
	}

	// L4 accepts are port-scoped per destination (Phase 3): the concatenated set
	// carries each allowlisted address paired with the ports it may be reached on,
	// and `ip daddr . th dport @set` matches an address only on its own ports. The
	// explicit `meta l4proto { tcp, udp }` restricts these accepts to TCP and UDP
	// (covering HTTPS/git/npm and QUIC/HTTP3-over-UDP) — WITHOUT it, `th dport` alone
	// does not assert the L4 protocol, so other IP protocols (raw IP, GRE, SCTP,
	// custom proto numbers) could slip through as a covert exfil channel to an
	// allowed host. With it, they fall through to the default deny. (An entry with no
	// explicit port inherited the global allowed_ports, else all ports.)
	for _, set := range []string{staticPortSetName(f.containerIP), dynamicPortSetName(f.containerIP)} {
		if err := f.addRuleWithMatch(f.containerIP, "0.0.0.0/0",
			[]string{"meta", "l4proto", "{", "tcp,", "udp", "}", "ip", "daddr", ".", "th", "dport", "@" + set}, "accept"); err != nil {
			return fmt.Errorf("failed to add allowlist L4 rule for set %s: %w", set, err)
		}
	}

	// ICMP echo-request is allowed but rate-limited (~10/s plus nft's default burst)
	// so ordinary ping and health checks work while ICMP cannot become a
	// high-bandwidth covert channel. It has no port, so it matches the address-only
	// sets (which stay populated in parallel with the port-scoped sets above).
	// Excess echo and all other ICMP types fall through to the default deny.
	for _, set := range []string{staticSetName(f.containerIP), dynamicSetName(f.containerIP)} {
		if err := f.addRuleWithMatch(f.containerIP, "@"+set,
			[]string{"icmp", "type", "echo-request", "limit", "rate", "10/second"}, "accept"); err != nil {
			return fmt.Errorf("failed to add allowlist ICMP rule for set %s: %w", set, err)
		}
	}

	// Default deny for allowlist mode
	if err := f.addRule(f.containerIP, "0.0.0.0/0", "reject"); err != nil {
		return fmt.Errorf("failed to add default deny rule: %w", err)
	}

	return nil
}

// RemoveRules removes every host-side artefact Coi installed for this container:
// forward rules, allowlist sets and the input-chain DNS block. See
// DeleteCOIFilterRulesForIP, which is the shared implementation and the same path
// kill and orphan cleanup take.
func (f *NftManager) RemoveRules() error {
	return DeleteCOIFilterRulesForIP(f.containerIP)
}

// ReplaceAllowlist re-syncs the static allowlist entries for this container.
//
// It no longer rewrites rules. The rules installed by ApplyAllowlist reference
// the container's sets by name and are stable for the life of the container, so
// updating the allowlist means adding set elements — which the kernel applies
// atomically, with no window in which a stale rule shadows a fresh one.
//
// The old implementation appended a new rule set behind the still-present
// default reject and then deleted the previous handles one exec at a time; for
// the duration of that teardown, any address present only in the new set was
// rejected. That window is gone: there is nothing to tear down.
//
// Dynamic (DNS-learned) addresses are not touched here — the resolver/refresher
// path (installNames → syncResolved → AllowDynamicIPs) owns them, and re-adding
// an element refreshes its timeout rather than replacing it, so an address that
// is still in use never expires out from under an open connection.
//
// This method is retained on the nftRuler interface as the static-entry re-sync
// primitive; a regression test pins that setup does not fall back to it.
func (f *NftManager) ReplaceAllowlist(cfg *config.NetworkConfig, staticCIDRs []string) error {
	if f.containerIP == "" {
		return nil
	}
	if err := f.ensureAllowlistSets(); err != nil {
		return err
	}
	// With cfg we recover the per-entry ports and re-sync BOTH sets from that single
	// source (as ApplyAllowlist does), so the address set and the port-scoped set the
	// L4 rules match stay in step. A nil cfg — only reachable via the interface, never
	// the setup path — has no port information, so it re-syncs addresses only.
	if cfg == nil {
		return f.AddStaticIPs(staticCIDRs)
	}
	allowedPorts, err := validateAllowedPorts(cfg.AllowedPorts)
	if err != nil {
		return err
	}
	policy, err := NewAllowPolicy(cfg.AllowedDomains)
	if err != nil {
		return fmt.Errorf("failed to compile allowed_domains: %w", err)
	}
	if err := f.AddStaticIPs(policy.StaticCIDRs()); err != nil {
		return err
	}
	return f.AddStaticTuples(policy.staticTuples(), intsToPortRanges(allowedPorts))
}

// EnsureBaseRules creates the ip coi table/chain and adds the shared conntrack rule.
func EnsureBaseRules() error {
	if err := ensureCOITableAndChain(); err != nil {
		return err
	}
	exists, err := nftRuleExistsWithComment("coi-base")
	if err != nil || exists {
		return err
	}
	_, err = runNFTCommand("add", "rule", "ip", "coi", "forward",
		"ct", "state", "established,related", "accept",
		"comment", `"coi-base"`)
	return err
}

// EnsureOpenModeRules adds an ACCEPT rule for all traffic from a container in open mode.
func EnsureOpenModeRules(containerIP string) error {
	if err := EnsureBaseRules(); err != nil {
		logWarnf("Warning: failed to ensure base rules: %v", err)
	}
	exists, err := nftRuleExistsWithComment("coi-" + containerIP)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = runNFTCommand("add", "rule", "ip", "coi", "forward",
		"ip", "saddr", containerIP,
		"accept",
		"comment", fmt.Sprintf(`"coi-%s"`, containerIP))
	if err != nil {
		return fmt.Errorf("failed to add open mode rule: %w", err)
	}
	return nil
}

// RemoveOpenModeRules removes the ACCEPT rules for a container in open mode.
func RemoveOpenModeRules(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	return deleteNFTRulesByComment("coi-" + containerIP)
}

// ApplyBootBlockRule installs a temporary iifname-based DROP rule in the
// ip coi forward chain immediately after a container starts, before any
// startup scripts can run. This closes the network gap between container boot
// and SetupForContainer installing proper IP-based isolation rules.
//
// The rule is keyed by comment "coi-boot-<containerName>" and must be lifted
// by RemoveBootBlockRule once proper isolation rules are in place. It is
// idempotent: calling it twice for the same container is safe.
//
// The veth interface is created by the kernel the moment Incus starts the
// container, before DHCP assigns an IP. We poll for it here so callers do
// not need to know the timing. Non-fatal path: if the veth does not appear
// within 5 s (e.g. nft unavailable, unusual networking) the error is returned
// and the caller should log a warning and continue.
func ApplyBootBlockRule(containerName string) error {
	if !SudoEnabled() {
		return nil // use_sudo=false: best-effort boot block skipped (no sudo)
	}
	if !NftInstalled() {
		return fmt.Errorf("nft not installed, boot block skipped")
	}
	if err := ensureCOITableAndChain(); err != nil {
		return fmt.Errorf("failed to ensure coi chain: %w", err)
	}

	// Poll for the host-side veth — it is created when Incus sets up the
	// container's network namespace, typically within a few hundred ms.
	const (
		pollInterval = 100 * time.Millisecond
		pollMax      = 20 // 2 s total
	)
	var vethName string
	for i := 0; i < pollMax; i++ {
		name, err := GetContainerVethName(containerName)
		if err == nil && name != "" {
			vethName = name
			break
		}
		time.Sleep(pollInterval)
	}
	if vethName == "" {
		return fmt.Errorf("veth for container %s did not appear within 2s", containerName)
	}

	comment := bootBlockComment(containerName)

	// Idempotent: skip if already installed.
	if exists, err := nftRuleExistsWithComment(comment); err == nil && exists {
		return nil
	}

	if _, err := runNFTCommand(
		"add", "rule", "ip", "coi", "forward",
		"iifname", vethName,
		"drop",
		"comment", fmt.Sprintf(`"%s"`, comment),
	); err != nil {
		return fmt.Errorf("failed to add boot block rule for %s (veth %s): %w", containerName, vethName, err)
	}
	return nil
}

// RemoveBootBlockRule removes the temporary boot-block rule installed by
// ApplyBootBlockRule. Safe to call even if no rule was ever installed.
func RemoveBootBlockRule(containerName string) error {
	if !SudoEnabled() {
		return nil // nothing was applied without sudo
	}
	return deleteNFTRulesByComment(bootBlockComment(containerName))
}

func bootBlockComment(containerName string) string {
	return "coi-boot-" + containerName
}

// DisableIPv6ForContainer disables IPv6 in the container to prevent firewall bypass.
// All Coi IPv4 nft rules are IPv4-only; IPv6 would circumvent them entirely.
//
// NOTE: this runs an in-container sysctl, which in-container root can simply set
// back to 0 (it owns CAP_NET_ADMIN over its own netns). It is therefore
// defence-in-depth only — the enforced IPv6 egress boundary is the host-side
// drop installed by ApplyIPv6BlockForContainer, which the container cannot touch.
func DisableIPv6ForContainer(containerName string) error {
	mgr := container.NewManager(containerName)
	cmd := "sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1"
	_, err := mgr.ExecCommand(cmd, container.ExecCommandOptions{Capture: true})
	return err
}

// ensureCOIIP6TableAndChain creates the ip6 coi table and forward chain if absent,
// mirroring ensureCOITableAndChain for IPv6. The chain hooks the forward path at
// priority 10 with a default-accept policy; the only rules Coi adds are
// per-container iifname drops, so unrelated IPv6 traffic on the host is unaffected.
func ensureCOIIP6TableAndChain() error {
	if _, err := runNFTCommand("add", "table", "ip6", "coi"); err != nil {
		return fmt.Errorf("failed to create nft table ip6 coi: %w", err)
	}
	// nft add chain with hook spec fails if the chain already exists — check first.
	if _, err := runNFTCommand("list", "chain", "ip6", "coi", "forward"); err == nil {
		return nil
	}
	_, err := runNFTCommand("add", "chain", "ip6", "coi", "forward",
		"{", "type", "filter", "hook", "forward", "priority", "10", ";", "policy", "accept", ";", "}")
	if err != nil {
		return fmt.Errorf("failed to create nft chain ip6 coi forward: %w", err)
	}
	return nil
}

func ipv6BlockComment(containerName string) string {
	return "coi6-" + containerName
}

// ApplyIPv6BlockForContainer installs a host-side nft rule that drops ALL
// forwarded IPv6 traffic originating from the container's host-side veth.
//
// This is the enforced IPv6 egress boundary. Because the rule lives in the
// host's ip6 table keyed on the veth interface name (Coi never assigns the
// container an IPv6 address, so address-based matching is impossible anyway),
// in-container root cannot remove it or bypass it by re-enabling IPv6. It must
// be called after the container is running so its veth exists. Used in
// restricted and allowlist modes; open mode skips it by design (the user opted
// into unrestricted egress).
func ApplyIPv6BlockForContainer(containerName string) error {
	if !NftInstalled() {
		return fmt.Errorf("nft not installed, IPv6 block skipped")
	}
	if err := ensureCOIIP6TableAndChain(); err != nil {
		return err
	}
	vethName, err := GetContainerVethName(containerName)
	if err != nil || vethName == "" {
		return fmt.Errorf("could not resolve veth for IPv6 block on %s: %w", containerName, err)
	}
	comment := ipv6BlockComment(containerName)
	// Idempotent: skip if already installed.
	if exists, err := nftRuleExistsWithCommentFamily("ip6", comment); err == nil && exists {
		return nil
	}
	if _, err := runNFTCommand(
		"add", "rule", "ip6", "coi", "forward",
		"iifname", vethName,
		"drop",
		"comment", fmt.Sprintf(`"%s"`, comment),
	); err != nil {
		return fmt.Errorf("failed to add IPv6 block rule for %s (veth %s): %w", containerName, vethName, err)
	}
	return nil
}

// RemoveIPv6BlockForContainer removes the host-side IPv6 egress drop rule installed
// by ApplyIPv6BlockForContainer. Safe to call even if no rule was ever installed.
func RemoveIPv6BlockForContainer(containerName string) error {
	return deleteNFTRulesByCommentFamily("ip6", ipv6BlockComment(containerName))
}

// ListCOIIP6RuleContainers returns the container names referenced by
// coi6-<name> comments in the ip6 coi forward chain. Used by orphan detection
// to find IPv6 drop rules whose containers are no longer running.
func ListCOIIP6RuleContainers() ([]string, error) {
	output, err := runNFTCommand("-a", "list", "chain", "ip6", "coi", "forward")
	if err != nil {
		return nil, nil // chain doesn't exist yet — no rules
	}
	return parseCOIIP6RuleContainers(string(output)), nil
}

// parseCOIIP6RuleContainers extracts the unique container names from coi6-<name>
// rule comments in `nft list chain ip6 coi forward` output. Pure, for testing.
func parseCOIIP6RuleContainers(output string) []string {
	var names []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		const prefix = `comment "coi6-`
		idx := strings.Index(line, prefix)
		if idx == -1 {
			continue
		}
		rest := line[idx+len(prefix):]
		end := strings.Index(rest, `"`)
		if end == -1 {
			continue
		}
		name := rest[:end]
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// addRule appends a nftables rule to ip coi forward for this container.
// Rules are appended in call order, so callers must invoke addRule from most-specific
// to least-specific (gateway → allowlist → RFC1918 block → default).
func (f *NftManager) addRule(source, destination, action string) error {
	return f.addRuleWithMatch(source, destination, nil, action)
}

// addRuleWithMatch is addRule with an optional extra match clause inserted
// between the daddr match and the action (e.g. an L4 protocol / ICMP-type
// constraint). match is a slice of nft tokens; nil/empty behaves like addRule.
func (f *NftManager) addRuleWithMatch(source, destination string, match []string, action string) error {
	args := []string{
		"add", "rule", "ip", "coi", "forward",
		"ip", "saddr", source,
	}
	// 0.0.0.0/0 matches all destinations — omit the daddr match for cleaner nft syntax
	if destination != "0.0.0.0/0" {
		args = append(args, "ip", "daddr", destination)
	}
	args = append(args, match...)
	args = append(args, action, "comment", fmt.Sprintf(`"coi-%s"`, f.containerIP))
	if f.batch != nil {
		f.batch = append(f.batch, args)
		return nil
	}
	if _, err := runNFTCommand(args...); err != nil {
		return fmt.Errorf("nft rule add failed: %w", err)
	}
	return nil
}

// ensureCOITableAndChain creates the ip coi table and forward chain if absent.
// The chain hooks into the forward path at priority 10, which runs after the
// nftmonitor chain at priority 0 so traffic is logged before being filtered.
func ensureCOITableAndChain() error {
	if _, err := runNFTCommand("add", "table", "ip", "coi"); err != nil {
		return fmt.Errorf("failed to create nft table ip coi: %w", err)
	}
	// nft add chain with hook spec fails if the chain already exists — check first.
	if _, err := runNFTCommand("list", "chain", "ip", "coi", "forward"); err == nil {
		return nil
	}
	_, err := runNFTCommand("add", "chain", "ip", "coi", "forward",
		"{", "type", "filter", "hook", "forward", "priority", "10", ";", "policy", "accept", ";", "}")
	if err != nil {
		return fmt.Errorf("failed to create nft chain ip coi forward: %w", err)
	}
	return nil
}

// nftRuleExistsWithComment returns true if any rule in ip coi forward carries the given comment.
func nftRuleExistsWithComment(comment string) (bool, error) {
	return nftRuleExistsWithCommentFamily("ip", comment)
}

// nftRuleExistsWithCommentFamily is the family-aware variant of
// nftRuleExistsWithComment ("ip" for IPv4, "ip6" for IPv6).
func nftRuleExistsWithCommentFamily(family, comment string) (bool, error) {
	output, err := runNFTCommand("list", "chain", family, "coi", "forward")
	if err != nil {
		return false, nil // chain doesn't exist yet
	}
	return strings.Contains(string(output), fmt.Sprintf(`comment "%s"`, comment)), nil
}

// nftGetHandlesByCommentFamily is the family-aware variant of
// nftGetHandlesByComment ("ip" for IPv4, "ip6" for IPv6).
func nftGetHandlesByCommentFamily(family, comment string) ([]string, error) {
	output, err := runNFTCommand("-a", "list", "chain", family, "coi", "forward")
	if err != nil {
		// A chain that was never created holds no rules — treating it as an
		// error made deleteNFTRulesByCommentFamily spin all 8 retry rounds
		// (~2s + 8 warnings) on hosts that never ran the family in question
		// (e.g. the ip6 chain in open network mode). Same for disabled sudo:
		// without it nothing can be listed OR deleted, so retrying is pure
		// stall. Both mean "nothing to delete here".
		msg := err.Error()
		if strings.Contains(msg, "No such file or directory") || strings.Contains(msg, "sudo disabled") {
			return nil, nil
		}
		return nil, err
	}
	var handles []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, fmt.Sprintf(`comment "%s"`, comment)) {
			if h := extractNFTHandle(line); h != "" {
				handles = append(handles, h)
			}
		}
	}
	return handles, nil
}

// deleteNFTRulesByComment removes all rules in ip coi forward that carry the given comment.
// It loops up to maxRounds times, re-scanning handles after each pass, so transient nft
// lock failures and any handles missed in earlier scans are retried automatically.
func deleteNFTRulesByComment(comment string) error {
	return deleteNFTRulesByCommentFamily("ip", comment)
}

// deleteNFTRulesByCommentFamily is the family-aware variant of
// deleteNFTRulesByComment ("ip" for IPv4, "ip6" for IPv6).
func deleteNFTRulesByCommentFamily(family, comment string) error {
	const (
		maxRounds = 8
		delay     = 300 * time.Millisecond
	)
	// Back off only after a failed list or delete (a transient nft lock). A
	// clean round re-lists at once: the re-list is the verification that
	// every matching rule is gone, and sleeping before it cost 300 ms on
	// every boot-block lift and stale-rule purge for nothing.
	backoff := false
	for round := 0; round < maxRounds; round++ {
		if backoff {
			time.Sleep(delay)
		}
		backoff = false
		handles, err := nftGetHandlesByCommentFamily(family, comment)
		if err != nil {
			logWarnf("Warning: nft list failed (round %d/%d): %v, retrying...", round+1, maxRounds, err)
			backoff = true
			continue
		}
		if len(handles) == 0 {
			return nil
		}
		for _, h := range handles {
			if _, delErr := runNFTCommand("delete", "rule", family, "coi", "forward", "handle", h); delErr != nil {
				logWarnf("Warning: failed to delete nft rule handle %s (round %d/%d): %v", h, round+1, maxRounds, delErr)
				backoff = true
			}
		}
	}
	return nil
}

// ListCOIFilterRuleIPs returns a map of container IP → rule handles from ip coi forward.
// Used by orphan detection to find rules whose containers are no longer running.
func ListCOIFilterRuleIPs() (map[string][]string, error) {
	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		return nil, nil
	}
	result := make(map[string][]string)
	for _, line := range strings.Split(string(output), "\n") {
		const prefix = `comment "coi-`
		idx := strings.Index(line, prefix)
		if idx == -1 {
			continue
		}
		rest := line[idx+len(prefix):]
		end := strings.Index(rest, `"`)
		if end == -1 {
			continue
		}
		ip := rest[:end]
		if ip == "base" {
			continue
		}
		if h := extractNFTHandle(line); h != "" {
			result[ip] = append(result[ip], h)
		}
	}
	return result, nil
}

// DeleteCOIFilterRulesForIP removes every host-side artefact Coi installed for a
// container IP: its forward rules, then its input-chain DNS block, then its
// allowlist sets.
//
// This is the single teardown entry point used by kill, orphan cleanup and
// setup's stale-rule purge, so it must account for everything allowlist mode
// creates: forward rules, the input-chain DNS block, and the two allowlist sets.
//
// Rules go first, in both chains — the kernel refuses to drop a set that a rule
// still references.
//
// It is safe for containers that never had sets or a DNS block (open and
// restricted mode): removing something that was never created is a no-op.
func DeleteCOIFilterRulesForIP(ip string) error {
	if ip == "" {
		return nil
	}
	if err := deleteNFTRulesByComment("coi-" + ip); err != nil {
		return err
	}
	if err := removeInputRulesForIP(ip); err != nil {
		return err
	}
	return removeAllowlistSetsForIP(ip)
}

// GetContainerIP retrieves the IPv4 address of a container from Incus
// It retries for up to 30 seconds waiting for DHCP to assign an IP
func GetContainerIP(containerName string) (string, error) {
	return GetContainerIPWithRetries(containerName, 30)
}

// GetContainerIPFast retrieves the container IP with minimal retries
func GetContainerIPFast(containerName string) (string, error) {
	return GetContainerIPWithRetries(containerName, 3)
}

// GetContainerIPWithRetries retrieves the IPv4 address, waiting up to
// maxRetries seconds for DHCP. It polls every ipPollInterval rather than once
// a second: on a just-(re)started container the lease usually lands a few
// hundred ms after start, and a 1 s step turned that into a full extra second
// of every launch.
func GetContainerIPWithRetries(containerName string, maxRetries int) (string, error) {
	deadline := time.Now().Add(time.Duration(maxRetries) * time.Second)
	var lastErr error
	for {
		ip, err := getContainerIPOnce(containerName)
		if err == nil {
			return ip, nil
		}
		lastErr = err
		if maxRetries <= 1 || !time.Now().Add(ipPollInterval).Before(deadline) {
			break
		}
		time.Sleep(ipPollInterval)
	}
	return "", fmt.Errorf("timeout waiting for container IP after %d seconds: %w", maxRetries, lastErr)
}

// ipPollInterval is how often GetContainerIPWithRetries re-checks for a lease.
const ipPollInterval = 200 * time.Millisecond

func getContainerIPOnce(containerName string) (string, error) {
	ip, _, err := lookupInstanceNet(containerName)
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", fmt.Errorf("no IPv4 address found for container %s", containerName)
	}
	return ip, nil
}

// instanceNet is a container's eth0 IPv4 address and host-side veth name.
type instanceNet struct {
	ip, veth string
	at       time.Time
}

// instanceNetCache remembers complete (IPv4 + veth) answers briefly: one
// launch asks for the IP and the veth 3-4 times (boot block, mode setup,
// IPv6 block, [[network.hosts]]), each a full-state `incus list` (~100-200 ms).
// Only complete answers are cached, so a container still waiting for its DHCP
// lease is always re-queried, and the short TTL covers just one launch.
var instanceNetCache sync.Map // container name -> instanceNet

const instanceNetTTL = 5 * time.Second

// lookupInstanceNet returns the container's eth0 IPv4 address and veth name
// (either may be empty) from one `incus list`.
func lookupInstanceNet(containerName string) (ip, veth string, err error) {
	if v, ok := instanceNetCache.Load(containerName); ok {
		// The veth is recreated on every container start: only trust a cached
		// answer whose veth still exists on the host.
		if n, ok := v.(instanceNet); ok && time.Since(n.at) < instanceNetTTL && hostInterfaceExists(n.veth) {
			return n.ip, n.veth, nil
		}
		instanceNetCache.Delete(containerName)
	}
	output, err := container.IncusOutput("list", containerName, "--format=json")
	if err != nil {
		return "", "", fmt.Errorf("failed to get container info: %w", err)
	}
	ip, veth, err = parseInstanceNet(output, containerName)
	if err != nil {
		return "", "", err
	}
	if ip != "" && veth != "" {
		instanceNetCache.Store(containerName, instanceNet{ip: ip, veth: veth, at: time.Now()})
	}
	return ip, veth, nil
}

// hostInterfaceExists reports whether a network interface exists on the host.
func hostInterfaceExists(name string) bool {
	if name == "" || strings.ContainsAny(name, "/.") {
		return false
	}
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

// parseInstanceNet extracts eth0's IPv4 address and host_name for
// containerName from `incus list --format=json` output.
func parseInstanceNet(output, containerName string) (ip, veth string, err error) {
	var containers []struct {
		Name  string `json:"name"`
		State struct {
			Network map[string]struct {
				HostName  string `json:"host_name"`
				Addresses []struct {
					Family  string `json:"family"`
					Address string `json:"address"`
				} `json:"addresses"`
			} `json:"network"`
		} `json:"state"`
	}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return "", "", fmt.Errorf("failed to parse container info: %w", err)
	}
	for _, c := range containers {
		if c.Name != containerName {
			continue
		}
		eth0, ok := c.State.Network["eth0"]
		if !ok {
			continue
		}
		veth = eth0.HostName
		for _, addr := range eth0.Addresses {
			if addr.Family == "inet" {
				ip = addr.Address
				break
			}
		}
	}
	return ip, veth, nil
}

// NftInstalled checks if the nft binary is installed
func NftInstalled() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// NftAvailable checks if nft is available and passwordless sudo is configured.
// Returns false without probing when sudo is disabled (use_sudo=false), so no
// callsite that gates on NftAvailable() ever shells out to sudo.
func NftAvailable() bool {
	if !SudoEnabled() {
		return false
	}
	cmd := exec.Command("sudo", "-n", "nft", "list", "tables")
	return cmd.Run() == nil
}

// NftPasswordlessSudo reports whether `sudo nft` works WITHOUT a password —
// i.e. a NOPASSWD rule is in effect — ignoring any cached sudo credential
// (`sudo -k -n`). NftAvailable can't tell those apart: right after the user
// typed a sudo password it succeeds for ~15 minutes, then isolation breaks.
// Health checks use this; runtime keeps NftAvailable (a cached credential does
// work for the moment).
func NftPasswordlessSudo() bool {
	if !SudoEnabled() {
		return false
	}
	return runSudoProbe("-k", "-n", "nft", "list", "tables") == nil
}

// runSudoProbe runs `sudo <args>`; a package var so tests can observe the args.
var runSudoProbe = func(args ...string) error {
	return exec.Command("sudo", args...).Run() //nolint:gosec // fixed args from NftPasswordlessSudo
}

// NftUsable reports whether Coi can actually use nft for the given config:
// config must permit sudo (`[network] use_sudo` != false) AND the passwordless
// sudo probe must succeed. When use_sudo=false this returns false without ever
// invoking sudo, so Coi behaves as if passwordless sudo were unavailable.
func NftUsable(cfg *config.NetworkConfig) bool {
	return cfg.SudoAllowed() && NftAvailable()
}

// UfwInstalled checks if the ufw binary is installed
func UfwInstalled() bool {
	_, err := exec.LookPath("ufw")
	return err == nil
}

// UfwActive checks if ufw is active.
func UfwActive() bool {
	if err := exec.Command("systemctl", "is-active", "--quiet", "ufw").Run(); err == nil {
		return true
	}
	out, err := exec.Command("sudo", "-n", "ufw", "status").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: active")
}

// MasqueradeEnabled checks if the Incus bridge has NAT (masquerade) enabled.
// Incus manages masquerade natively via its bridge config; no extra firewall daemon needed.
// ipv4.nat defaults to true for Incus-managed bridges; an unset/empty value
// means the default (enabled), so only an explicit "false" means disabled.
func MasqueradeEnabled() bool {
	bridgeName, err := GetIncusBridgeName()
	if err != nil {
		return false
	}
	output, err := container.IncusOutput("network", "get", bridgeName, "ipv4.nat")
	if err != nil {
		return false
	}
	val := strings.TrimSpace(output)
	return val != "false" // empty string = default = enabled
}

// BridgeInTrustedZone checks whether the Incus bridge has iptables FORWARD ACCEPT
// rules in place (the nft-based replacement for iptables bridge forwarding rules).
// Returns (inZone, bridgeName, error).
func BridgeInTrustedZone() (bool, string, error) {
	bridgeName, err := GetIncusBridgeName()
	if err != nil {
		return false, "", fmt.Errorf("could not determine bridge name: %w", err)
	}
	return IptablesBridgeRulesExist(bridgeName), bridgeName, nil
}

// EnsureBridgeInTrustedZone ensures the Incus bridge has iptables FORWARD ACCEPT
// rules so containers can obtain IPs via DHCP even when the FORWARD policy is DROP.
// Returns (changed, bridgeName, error).
func EnsureBridgeInTrustedZone() (bool, string, error) {
	bridgeName, err := GetIncusBridgeName()
	if err != nil {
		return false, "", fmt.Errorf("could not determine bridge name: %w", err)
	}
	if IptablesBridgeRulesExist(bridgeName) {
		return false, bridgeName, nil
	}
	if err := EnsureIptablesBridgeRules(bridgeName); err != nil {
		return false, bridgeName, err
	}
	return true, bridgeName, nil
}

// IptablesAvailable checks if the iptables binary is installed
func IptablesAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

// ForwardPolicyIsDrop checks if the iptables FORWARD chain policy is DROP
func ForwardPolicyIsDrop() bool {
	if !SudoEnabled() {
		return false // can't (and won't) probe iptables without sudo
	}
	cmd := exec.Command("sudo", "-n", "iptables", "-L", "FORWARD", "-n")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	lines := strings.SplitN(string(output), "\n", 2)
	if len(lines) == 0 {
		return false
	}
	return strings.Contains(lines[0], "policy DROP")
}

// NeedsIptablesFallback returns true when nft is not available but
// the FORWARD chain policy is DROP and iptables is available as a fallback
func NeedsIptablesFallback() bool {
	if !SudoEnabled() {
		return false // iptables fallback also needs sudo
	}
	return !NftAvailable() && ForwardPolicyIsDrop() && IptablesAvailable()
}

// GetIncusBridgeName extracts the bridge/network name from the Incus default profile
func GetIncusBridgeName() (string, error) {
	bridgeNameMu.Lock()
	defer bridgeNameMu.Unlock()
	if bridgeName != "" {
		return bridgeName, nil
	}
	name, err := lookupIncusBridgeName()
	if err == nil {
		bridgeName = name
	}
	return name, err
}

// bridgeName memoizes GetIncusBridgeName's answer for the process: the default
// profile's network doesn't change under a running coi, and a launch asked
// for it twice (bridge trust check, gateway lookup). Only successes are kept.
var (
	bridgeNameMu sync.Mutex
	bridgeName   string
)

func lookupIncusBridgeName() (string, error) {
	profileOutput, err := container.IncusOutput("profile", "device", "show", "default")
	if err != nil {
		return "", fmt.Errorf("failed to get default profile: %w", err)
	}

	lines := strings.Split(profileOutput, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "eth0:" {
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				if strings.Contains(lines[j], "network:") {
					parts := strings.Split(lines[j], ":")
					if len(parts) >= 2 {
						return strings.TrimSpace(parts[1]), nil
					}
				}
			}
			break
		}
	}
	return "", fmt.Errorf("could not determine network/bridge name from default profile")
}

// EnsureIptablesBridgeRules idempotently adds FORWARD ACCEPT rules for the
// given bridge interface. The rules are tagged with a comment so they can be
// identified for cleanup.
func EnsureIptablesBridgeRules(bridgeName string) error {
	rules := [][]string{
		{"-i", bridgeName, "-j", "ACCEPT", "-m", "comment", "--comment", "coi-bridge-forward"},
		{"-o", bridgeName, "-j", "ACCEPT", "-m", "comment", "--comment", "coi-bridge-forward"},
	}

	for _, ruleSpec := range rules {
		if iptablesRuleExists("FORWARD", ruleSpec...) {
			continue
		}
		args := append([]string{"-n", "iptables", "-I", "FORWARD"}, ruleSpec...)
		cmd := exec.Command("sudo", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to add iptables rule: %s: %w", strings.TrimSpace(string(output)), err)
		}
	}
	return nil
}

// RemoveIptablesBridgeRules removes the coi-bridge-forward iptables rules.
func RemoveIptablesBridgeRules(bridgeName string) error {
	rules := [][]string{
		{"-i", bridgeName, "-j", "ACCEPT", "-m", "comment", "--comment", "coi-bridge-forward"},
		{"-o", bridgeName, "-j", "ACCEPT", "-m", "comment", "--comment", "coi-bridge-forward"},
	}

	for _, ruleSpec := range rules {
		if !iptablesRuleExists("FORWARD", ruleSpec...) {
			continue
		}
		args := append([]string{"-n", "iptables", "-D", "FORWARD"}, ruleSpec...)
		cmd := exec.Command("sudo", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to remove iptables rule: %s: %w", strings.TrimSpace(string(output)), err)
		}
	}
	return nil
}

// IptablesBridgeRulesExist checks whether the coi-bridge-forward rules exist
func IptablesBridgeRulesExist(bridgeName string) bool {
	inRule := iptablesRuleExists("FORWARD",
		"-i", bridgeName, "-j", "ACCEPT", "-m", "comment", "--comment", "coi-bridge-forward")
	outRule := iptablesRuleExists("FORWARD",
		"-o", bridgeName, "-j", "ACCEPT", "-m", "comment", "--comment", "coi-bridge-forward")
	return inRule && outRule
}

func iptablesRuleExists(chain string, ruleSpec ...string) bool {
	args := append([]string{"-n", "iptables", "-C", chain}, ruleSpec...)
	cmd := exec.Command("sudo", args...)
	return cmd.Run() == nil
}

// IsDockerRunning checks if the Docker daemon is running
func IsDockerRunning() bool {
	if exec.Command("systemctl", "is-active", "--quiet", "docker").Run() == nil {
		return true
	}
	return exec.Command("pgrep", "-x", "dockerd").Run() == nil
}

// GetContainerVethName retrieves the host-side veth interface name for a container
func GetContainerVethName(containerName string) (string, error) {
	_, veth, err := lookupInstanceNet(containerName)
	if err != nil {
		return "", err
	}
	if veth == "" {
		return "", fmt.Errorf("no veth interface found for container %s", containerName)
	}
	return veth, nil
}
