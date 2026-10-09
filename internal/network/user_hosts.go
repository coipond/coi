package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// hostIPClass classifies a host-entry address for reachability decisions.
type hostIPClass int

const (
	hostPublic   hostIPClass = iota // routable internet address
	hostPrivate                     // RFC1918 (10/8, 172.16/12, 192.168/16) or ULA
	hostMetadata                    // 169.254.0.0/16 link-local, incl. the cloud metadata endpoint
)

// classifyHostIP buckets an address for the per-mode reachability rules. The IP
// is assumed already validated as a parseable IPv4 (config.ValidateNetworkHosts).
func classifyHostIP(ipStr string) hostIPClass {
	ip := net.ParseIP(ipStr)
	switch {
	case ip == nil:
		return hostPublic // unreachable in practice — validation rejects non-IPs
	case ip.IsLinkLocalUnicast():
		return hostMetadata
	case ip.IsPrivate():
		return hostPrivate
	default:
		return hostPublic
	}
}

// checkHostReachable reports whether a host entry's address CAN be made reachable
// under the given mode. It refuses addresses the mode hard-blocks, so we never
// write a /etc/hosts name that resolves to a permanently-unreachable address.
// Private (RFC1918) addresses are reachable in every mode — restricted and
// allowlist via a targeted accept, or allowlist's allow_local_network_access LAN
// accept — so whether one is acceptable is a port-scope question, answered by
// checkHostPortsEnforceable.
func checkHostReachable(mode config.NetworkMode, ipStr string) error {
	// Refused in every enforcing mode regardless of allow_local_network_access:
	// pointing a name at 169.254.0.0/16 (cloud metadata) is a credential-theft
	// SSRF vector. Even with local access on, allowlist mode installs an RFC1918
	// accept but NOT a metadata one, so the address stays unreachable anyway.
	if classifyHostIP(ipStr) == hostMetadata &&
		(mode == config.NetworkModeRestricted || mode == config.NetworkModeAllowlist) {
		return fmt.Errorf(
			"network.hosts: %s is in the link-local/metadata range (169.254.0.0/16), refused in %s mode "+
				"(cloud-metadata SSRF)", ipStr, mode)
	}
	return nil
}

// checkHostPortsEnforceable refuses a per-host `ports` scope that the active
// mode/class combination cannot actually enforce, rather than silently ignoring
// it (a false sense of security). Per-host ports take effect for a private host
// in restricted mode and in allowlist mode (targeted allow), and for a public
// host in allowlist mode (port-scoped set tuple). Everywhere else the host is
// reached — if at all — through a broader rule (restricted's blanket internet
// accept, or allowlist's allow_local_network_access LAN accept scoped by the
// GLOBAL allowed_ports), so a per-host cap would do nothing. It fails closed with
// a message that says why and what to do instead.
//
// A private host in allowlist mode without allow_local_network_access gets a
// targeted accept ahead of the RFC1918 block, which must be port-scoped (the
// entry's ports, else the global allowed_ports) and must not include 53:
// allowlist mode blocks all DNS so /etc/hosts stays the container's only
// resolver, and an all-ports or :53 hole to a LAN resolver would reopen DNS —
// and with it DNS tunnelling out past the allowlist.
func checkHostPortsEnforceable(mode config.NetworkMode, allowLocalNetworkAccess bool, entry config.HostEntry, allowedPorts []int) error {
	class := classifyHostIP(entry.IP)
	if mode == config.NetworkModeAllowlist && class == hostPrivate && !allowLocalNetworkAccess {
		scope := entry.Ports
		if len(scope) == 0 {
			scope = allowedPorts
		}
		if len(scope) == 0 {
			return fmt.Errorf("network.hosts: %s is a private address; allowlist mode opens a LAN host only on "+
				"explicit ports — set ports (e.g. ports = [443]) on this entry, or a global allowed_ports", entry.IP)
		}
		for _, p := range scope {
			if p == 53 {
				return fmt.Errorf("network.hosts: %s may not be opened on port 53 in allowlist mode, which blocks "+
					"all DNS by design (names resolve on the host into /etc/hosts) — drop 53 from its ports", entry.IP)
			}
		}
		return nil // enforced by a targeted, port-scoped accept
	}
	if len(entry.Ports) == 0 {
		return nil // no per-host ports to enforce
	}
	if (mode == config.NetworkModeRestricted && class == hostPrivate) ||
		(mode == config.NetworkModeAllowlist && class == hostPublic) {
		return nil // enforceable
	}
	switch {
	case mode == config.NetworkModeOpen:
		return fmt.Errorf("network.hosts: %s sets ports=%v, but open mode enforces no egress restrictions "+
			"so the port scope would do nothing — remove ports, or use restricted/allowlist mode", entry.IP, entry.Ports)
	case mode == config.NetworkModeRestricted && class == hostPublic:
		return fmt.Errorf("network.hosts: %s is a public address, which restricted mode already reaches on ALL "+
			"ports, so ports=%v cannot scope it — per-host ports here apply only to a private (LAN) address; "+
			"use allowlist mode to port-scope a public host", entry.IP, entry.Ports)
	case mode == config.NetworkModeAllowlist && class == hostPrivate:
		return fmt.Errorf("network.hosts: %s sets ports=%v, but allow_local_network_access already opens the "+
			"whole LAN on the global allowed_ports, so a per-host scope cannot narrow it — drop the per-host "+
			"ports, or turn allow_local_network_access off to reach only this LAN host", entry.IP, entry.Ports)
	default:
		return fmt.Errorf("network.hosts: %s ports=%v cannot be enforced for this address in %s mode",
			entry.IP, entry.Ports, mode)
	}
}

// ApplyUserHosts writes the static host entries ([[network.hosts]] / `coi hosts`,
// #605) into the container's /etc/hosts and makes each address reachable under the
// active network mode. Reachability is validated for EVERY entry up front, so a
// refused entry aborts before any /etc/hosts or firewall change. Works on a
// running container. An empty slice clears the managed block.
func ApplyUserHosts(containerName string, mode config.NetworkMode, allowLocalNetworkAccess bool, entries []config.HostEntry, allowedPorts []int) error {
	if len(entries) == 0 {
		return WriteUserHosts(containerName, nil)
	}
	if mode == "" {
		mode = config.NetworkModeRestricted // the config default
	}

	// 1. Fail before touching anything if any entry can't be made reachable, or
	// carries a per-host port scope this mode/class can't actually enforce.
	for _, e := range entries {
		if err := checkHostReachable(mode, e.IP); err != nil {
			return err
		}
		if err := checkHostPortsEnforceable(mode, allowLocalNetworkAccess, e, allowedPorts); err != nil {
			return err
		}
	}

	// 2. Firewall reachability (open mode needs none — nothing is blocked there).
	if mode == config.NetworkModeRestricted || mode == config.NetworkModeAllowlist {
		containerIP, err := GetContainerIP(containerName)
		if err != nil {
			return fmt.Errorf("failed to get container IP for host reachability: %w", err)
		}
		for _, e := range entries {
			if err := applyHostFirewall(mode, allowLocalNetworkAccess, containerIP, e, allowedPorts); err != nil {
				return err
			}
		}
	}

	// 3. Write /etc/hosts (all modes).
	return WriteUserHosts(containerName, entries)
}

// ReadUserHosts returns the host entries currently in the container's Coi
// user-hosts /etc/hosts block (empty if none). Used by `coi hosts list/add/remove`
// to read-modify-write the block on a running container.
func ReadUserHosts(containerName string) ([]config.HostEntry, error) {
	mgr := container.NewManager(containerName)
	out, err := mgr.ExecCommand("cat /etc/hosts", container.ExecCommandOptions{Capture: true})
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/hosts: %w", err)
	}
	return parseUserHostsBlock(out), nil
}

// parseUserHostsBlock extracts the entries between the user-hosts markers. Pure,
// so it is unit-testable without a container.
func parseUserHostsBlock(hostsFile string) []config.HostEntry {
	var entries []config.HostEntry
	inBlock := false
	for _, line := range strings.Split(hostsFile, "\n") {
		switch {
		case strings.HasPrefix(line, userHostsBeginMarker):
			inBlock = true
		case strings.HasPrefix(line, userHostsEndMarker):
			inBlock = false
		case inBlock:
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				entries = append(entries, config.HostEntry{IP: fields[0], Hostnames: fields[1:]})
			}
		}
	}
	return entries
}

// AddUserHost adds (or, for an existing IP, extends the hostnames of) one host
// entry on a running container: it applies firewall reachability for the address
// under the active mode, then merges the entry into the /etc/hosts user block.
func AddUserHost(containerName string, mode config.NetworkMode, allowLocalNetworkAccess bool, entry config.HostEntry, allowedPorts []int) error {
	if err := config.ValidateNetworkHosts([]config.HostEntry{entry}); err != nil {
		return err
	}
	if mode == "" {
		mode = config.NetworkModeRestricted
	}
	containerIP, err := GetContainerIP(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container IP: %w", err)
	}
	// The runtime CLI is invoked with whatever config the caller happens to have,
	// which may not be the one the container was launched with. Trusting it would
	// let `coi hosts add` punch a restricted-style targeted allow — unscoped, or on
	// :53 — through an allowlist container's RFC1918 and DNS blocks, skipping the
	// port-scope checks allowlist mode requires. Detect the container's ACTUAL mode
	// and honor that instead.
	mode = effectiveContainerMode(containerIP, mode)
	if err := checkHostReachable(mode, entry.IP); err != nil {
		return err
	}
	if err := checkHostPortsEnforceable(mode, allowLocalNetworkAccess, entry, allowedPorts); err != nil {
		return err
	}
	// Firewall reachability for just this address (open mode needs none). The port
	// cap is taken from the caller's config; like mode above it may be stale
	// relative to the container's launch config, but scoping to the caller's
	// allowed_ports is strictly tighter than the previous all-ports hole.
	if mode == config.NetworkModeRestricted || mode == config.NetworkModeAllowlist {
		if err := applyHostFirewall(mode, allowLocalNetworkAccess, containerIP, entry, allowedPorts); err != nil {
			return err
		}
	}
	// Merge into the existing block (union hostnames for a repeated IP).
	existing, err := ReadUserHosts(containerName)
	if err != nil {
		return err
	}
	return WriteUserHosts(containerName, mergeHostEntry(existing, entry))
}

// effectiveContainerMode returns the mode the container is ACTUALLY enforcing,
// used to override a possibly-stale caller-supplied mode for the runtime CLI. An
// allowlist container has its named sets present — that presence is the tell, and
// the case that matters for safety (never punch a hole through an allowlist
// container). When no allowlist set exists, the container is restricted or open;
// those are indistinguishable from nft state cheaply, and the difference is only
// about reachability (not a downgrade), so the caller's mode is used.
func effectiveContainerMode(containerIP string, configMode config.NetworkMode) config.NetworkMode {
	if containerIP != "" {
		if _, err := runNFTCommand("-j", "list", "set", "ip", "coi", staticSetName(containerIP)); err == nil {
			return config.NetworkModeAllowlist
		}
	}
	return configMode
}

// RemoveUserHost drops the given hostnames from the container's user-hosts block
// and rewrites it. Firewall reachability opened for the address is left in place;
// it is session-scoped and torn down when the container stops.
func RemoveUserHost(containerName string, hostnames []string) ([]config.HostEntry, error) {
	existing, err := ReadUserHosts(containerName)
	if err != nil {
		return nil, err
	}
	drop := make(map[string]bool, len(hostnames))
	for _, h := range hostnames {
		drop[h] = true
	}
	var kept []config.HostEntry
	for _, e := range existing {
		var names []string
		for _, n := range e.Hostnames {
			if !drop[n] {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			kept = append(kept, config.HostEntry{IP: e.IP, Hostnames: names})
		}
	}
	if err := WriteUserHosts(containerName, kept); err != nil {
		return nil, err
	}
	return kept, nil
}

// mergeHostEntry returns a NEW slice with `add` merged in: if its IP already
// exists, the hostname sets are unioned; otherwise it is appended. It does not
// mutate the input.
func mergeHostEntry(entries []config.HostEntry, add config.HostEntry) []config.HostEntry {
	out := make([]config.HostEntry, 0, len(entries)+1)
	merged := false
	for _, e := range entries {
		if e.IP != add.IP {
			out = append(out, e)
			continue
		}
		seen := make(map[string]bool, len(e.Hostnames))
		names := append([]string(nil), e.Hostnames...)
		for _, n := range names {
			seen[n] = true
		}
		for _, n := range add.Hostnames {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
		out = append(out, config.HostEntry{IP: e.IP, Hostnames: names})
		merged = true
	}
	if !merged {
		out = append(out, add)
	}
	return out
}

// applyHostFirewall applies reachability for a single entry under an enforcing
// mode (caller ensures mode is restricted/allowlist and the entry passed
// checkHostReachable and checkHostPortsEnforceable).
func applyHostFirewall(mode config.NetworkMode, allowLocalNetworkAccess bool, containerIP string, entry config.HostEntry, allowedPorts []int) error {
	class := classifyHostIP(entry.IP)
	// This entry's own ports scope its reachability (e.g. redmine on 443 only);
	// with none configured it inherits the global allowed_ports (else all ports).
	// This is what lets restricted mode open one LAN service on one port while the
	// rest of egress stays wide open — allowed_ports alone can't, since it is global.
	hostPorts := entry.Ports
	if len(hostPorts) == 0 {
		hostPorts = allowedPorts
	}
	// Normalize (range-check + dedup + sort) so the emitted rule is deterministic
	// and duplicate-free, exactly as the global allowed_ports path does — entry.Ports
	// otherwise reaches nft raw from config.
	hostPorts, err := validateAllowedPorts(hostPorts)
	if err != nil {
		// Both entry.Ports (config load) and the global allowed_ports (ApplyRestricted/
		// ApplyAllowlist) are already validated, so this is practically unreachable —
		// but attribute it to the host entry rather than let validateAllowedPorts'
		// "allowed_ports:" wording misdirect.
		return fmt.Errorf("network.hosts %s: invalid ports: %w", entry.IP, err)
	}
	switch {
	case mode == config.NetworkModeAllowlist && class == hostPublic:
		// Allowlist mode keeps addresses in two parallel sets: the address-only set
		// (ICMP + the security monitor) and the port-scoped concatenated set the L4
		// accept matches. Add this host to BOTH — the tuple scoped to hostPorts, so it
		// inherits the same cap every other allowlisted host does and cannot silently
		// reopen the full port range on a LAN box.
		nm := NewNftManager(containerIP, "")
		if err := nm.AddStaticIPs([]string{entry.IP}); err != nil {
			return fmt.Errorf("failed to allow host %s in allowlist mode: %w", entry.IP, err)
		}
		if err := nm.AddStaticTuples([]staticTuple{{CIDR: entry.IP}}, intsToPortRanges(hostPorts)); err != nil {
			return fmt.Errorf("failed to port-scope host %s in allowlist mode: %w", entry.IP, err)
		}
	case class == hostPrivate && (mode == config.NetworkModeRestricted || !allowLocalNetworkAccess):
		// A targeted accept ahead of the mode's RFC1918 reject. In allowlist mode it
		// also precedes the DNS block, which is why checkHostPortsEnforceable insists
		// on a port scope without 53. (With allow_local_network_access on, allowlist's
		// LAN accept already covers the host, so no rule is added.)
		if err := insertContainerAcceptRule(containerIP, entry.IP, hostPorts); err != nil {
			return fmt.Errorf("failed to allow private host %s in %s mode: %w", entry.IP, mode, err)
		}
	}
	return nil
}

// insertContainerAcceptRule PREPENDS an accept rule to the coi forward chain for
// traffic from containerIP to a specific destination, so it is evaluated before
// the mode's RFC1918 reject. Tagged with the same `coi-<ip>` comment the other
// per-container rules use, so it is torn down by the existing cleanup path.
//
// When an egress port cap (allowed_ports) is in force the accept is scoped to
// those TCP/UDP dports, so a [[network.hosts]] entry cannot silently reopen the
// full port range (SSH, databases, device admin) on a LAN host — the same
// guarantee allowed_ports makes for every other destination. ICMP echo to the
// host still works via the mode's global rate-limited echo-request accept. With
// no cap it stays the historic all-protocol accept.
func insertContainerAcceptRule(containerIP, destIP string, allowedPorts []int) error {
	if _, err := runNFTCommand(containerAcceptRuleArgs(containerIP, destIP, allowedPorts)...); err != nil {
		return fmt.Errorf("nft insert accept rule failed: %w", err)
	}
	return nil
}

// containerAcceptRuleArgs builds the nft `insert` token slice for a host-entry
// accept. Split out from insertContainerAcceptRule so the port-scoping is unit
// testable without invoking nft.
func containerAcceptRuleArgs(containerIP, destIP string, allowedPorts []int) []string {
	args := []string{
		"insert", "rule", "ip", "coi", "forward",
		"ip", "saddr", containerIP,
		"ip", "daddr", destIP + "/32",
	}
	if len(allowedPorts) > 0 {
		args = append(args, l4PortMatch(allowedPorts)...)
	}
	return append(args, "accept", "comment", fmt.Sprintf(`"coi-%s"`, containerIP))
}
