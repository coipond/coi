package network

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/coipond/coi/internal/config"
)

// This file holds the egress-policy primitives shared by restricted and allowlist
// mode: DNS resolver pinning (dns_servers) and destination-port capping
// (allowed_ports). The rule-emission helpers build nft token slices for
// addRuleWithMatch; see nft_filter.go for how the two modes wire them in.

// validateDNSServers normalises and checks the pinned-resolver list. Each entry
// must be a literal IPv4 address — a hostname is useless as a DNS pin (there is
// no resolver yet to resolve it, and in the modes this runs in DNS is exactly
// what is being constrained). Returns the addresses in canonical /32-less form.
func validateDNSServers(servers []string) ([]string, error) {
	out := make([]string, 0, len(servers))
	seen := make(map[string]bool)
	for _, s := range servers {
		t := strings.TrimSpace(s)
		ip := net.ParseIP(t)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("dns_servers: %q is not a valid IPv4 address", s)
		}
		canon := ip.To4().String()
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	return out, nil
}

// validateAllowedPorts checks the port allowlist and returns it deduplicated and
// sorted (deterministic nft output, stable tests).
func validateAllowedPorts(ports []int) ([]int, error) {
	seen := make(map[int]bool)
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("allowed_ports: %d is out of range (1-65535)", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

// portSetTokens renders a destination-port set as nft tokens, e.g. [80,443] ->
// "{", "80,", "443", "}". Callers splice it after "th", "dport". Ports are assumed
// already validated (1-65535) and non-empty. A single-element set ("{ 443 }") is
// valid nft, so no special case is needed.
func portSetTokens(ports []int) []string {
	toks := make([]string, 0, len(ports)+2)
	toks = append(toks, "{")
	for i, p := range ports {
		if i < len(ports)-1 {
			toks = append(toks, fmt.Sprintf("%d,", p))
		} else {
			toks = append(toks, fmt.Sprintf("%d", p))
		}
	}
	return append(toks, "}")
}

// l4PortMatch builds the "allow TCP/UDP" match used by the accept rules, adding a
// destination-port constraint when ports is non-empty. With no ports it reproduces
// the historic match exactly (meta l4proto { tcp, udp }), so existing configs emit
// byte-identical rules.
func l4PortMatch(ports []int) []string {
	match := []string{"meta", "l4proto", "{", "tcp,", "udp", "}"}
	if len(ports) > 0 {
		match = append(match, "th", "dport")
		match = append(match, portSetTokens(ports)...)
	}
	return match
}

// addLocalNetworkAllows opens the private ranges (config.PrivateNetworkCIDRs)
// for allow_local_network_access.
//
// When allowed_ports is set the accept is scoped to those destination ports, so
// the egress port cap applies to LAN traffic too: a compromised container must
// not gain all-ports reach to the local network — the prime lateral-movement
// target (SSH, databases, device admin panels) — merely because local access is
// enabled. This keeps allowed_ports and dns_servers consistent: both filter LAN
// traffic just as they filter internet traffic (dns_servers already restricts
// :53 everywhere via pinDNSForward, which runs before this).
//
// With no port cap it is the historic all-protocol blanket accept, so configs
// that do not set allowed_ports emit byte-identical rules.
func (f *NftManager) addLocalNetworkAllows(allowedPorts []int) error {
	for _, cidr := range config.PrivateNetworkCIDRs() {
		if len(allowedPorts) > 0 {
			if err := f.addRuleWithMatch(f.containerIP, cidr, l4PortMatch(allowedPorts), "accept"); err != nil {
				return fmt.Errorf("failed to add port-scoped private network allow rule: %w", err)
			}
		} else if err := f.addRule(f.containerIP, cidr, "accept"); err != nil {
			return fmt.Errorf("failed to add private network allow rule: %w", err)
		}
	}
	return nil
}

// pinDNSForward restricts the container's off-box DNS to a fixed set of resolvers.
// It accepts port 53 to each pinned server, then rejects port 53 to everything
// else — all in the forward chain, so a compromised container cannot reach an
// arbitrary public resolver (8.8.8.8, 1.1.1.1) or a resolver it hardcoded.
//
// Only the forward path is touched. The bridge's own resolver is addressed to the
// host and travels the input chain, so leaving input alone keeps the container's
// normal DHCP-provided resolution working while still blocking the bypass paths
// this exists to close. It is therefore safe to enable without also rewriting the
// container's resolv.conf.
//
// Ordering matters and is the caller's responsibility: pinDNSForward must run
// AFTER the gateway accept and BEFORE the RFC1918 block, so a pinned resolver that
// lives on the LAN (a typical Pi-hole at 192.168.x.y) is reachable on 53 even when
// private networks are otherwise blocked — but reachable on 53 ONLY, never on
// other ports.
func (f *NftManager) pinDNSForward(servers []string) error {
	if f.containerIP == "" || len(servers) == 0 {
		return nil
	}
	dnsMatch := []string{"meta", "l4proto", "{", "tcp,", "udp", "}", "th", "dport", "53"}
	for _, s := range servers {
		if err := f.addRuleWithMatch(f.containerIP, s+"/32", dnsMatch, "accept"); err != nil {
			return fmt.Errorf("failed to add DNS pin accept for %s: %w", s, err)
		}
	}
	// Reject every other route to a resolver so the pinned servers are the only
	// off-box DNS the container can reach.
	if err := f.addRuleWithMatch(f.containerIP, "0.0.0.0/0", dnsMatch, "reject"); err != nil {
		return fmt.Errorf("failed to add DNS pin reject: %w", err)
	}
	return nil
}
