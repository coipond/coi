package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/coipond/coi/internal/config"
)

// Traffic a container sends to the host itself — the bridge gateway, or any
// other address the host owns — is delivered through the input hook and never
// traverses the forward chain, so the forward rules of restricted and allowlist
// mode do not apply to it. The rules built here filter that path in the coi
// input chain. They carry the container's `coi-<ip>` comment, so every path
// that removes its forward rules (teardown, kill, stale and orphan purge)
// removes them too (see removeInputRulesForIP).

// hostIPv4Addrs returns the IPv4 addresses of the host's interfaces. A package
// var so tests can stub it.
var hostIPv4Addrs = func() map[string]bool {
	addrs := make(map[string]bool)
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return addrs
	}
	for _, a := range ifAddrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				addrs[ip4.String()] = true
			}
		}
	}
	return addrs
}

// hostPortAccept opens one host address to the container on the given ports.
type hostPortAccept struct {
	IP    string
	Ports []portRange
}

// hostInputRuleCmds builds the container's input-chain rules, in order:
// replies to connections the container already has, DHCP and ping to the
// gateway, DNS to the gateway (restricted mode only; allowlist mode rejects
// it in blockDNS, ahead of these rules), the accepts, then a reject for
// everything else.
//
// Without a known gateway (restricted mode tolerates that) DHCP and DNS are
// accepted to any host address, so the lease and the bridge resolver keep
// working; every other port stays closed.
func hostInputRuleCmds(containerIP, gatewayIP string, mode config.NetworkMode, accepts []hostPortAccept) [][]string {
	rule := func(match ...string) []string {
		args := []string{"add", "rule", "ip", "coi", "input", "ip", "saddr", containerIP}
		args = append(args, match...)
		return append(args, "comment", fmt.Sprintf(`"coi-%s"`, containerIP))
	}
	toGateway := func(match ...string) []string {
		if gatewayIP == "" {
			return match
		}
		return append([]string{"ip", "daddr", gatewayIP}, match...)
	}

	cmds := [][]string{rule("ct", "state", "established,related", "accept")}
	// A renewal goes to the gateway; a rebind after a failed renewal is a
	// broadcast.
	dhcp := []string{"udp", "dport", "67", "accept"}
	if gatewayIP != "" {
		dhcp = append([]string{"ip", "daddr", "{", gatewayIP + ",", "255.255.255.255", "}"}, dhcp...)
	}
	cmds = append(cmds, rule(dhcp...))
	if gatewayIP != "" {
		// Ping to the gateway stays a working connectivity check, rate-limited as
		// in the forward chain.
		cmds = append(cmds, rule("ip", "daddr", gatewayIP, "icmp", "type", "echo-request", "limit", "rate", "10/second", "accept"))
	}
	if mode == config.NetworkModeRestricted {
		cmds = append(cmds, rule(toGateway("meta", "l4proto", "{", "tcp,", "udp", "}", "th", "dport", "53", "accept")...))
	}
	for _, a := range accepts {
		cmds = append(cmds, rule(hostAcceptMatch(a)...))
	}
	return append(cmds, rule(tcpReset...), rule("reject"))
}

// hostAcceptMatch is the match and verdict of a hostPortAccept rule.
func hostAcceptMatch(a hostPortAccept) []string {
	match := []string{"ip", "daddr", a.IP, "meta", "l4proto", "{", "tcp,", "udp", "}", "th", "dport", "{"}
	for i, r := range a.Ports {
		v := r.nftValue()
		if i < len(a.Ports)-1 {
			v += ","
		}
		match = append(match, v)
	}
	return append(match, "}", "accept")
}

// hostAcceptPorts returns ports to open on a host address, without the DNS
// ports in allowlist mode (which blocks all DNS so /etc/hosts stays the
// container's only resolver). Empty means the address stays closed: the host
// opens only on ports an entry names.
func hostAcceptPorts(mode config.NetworkMode, ports []portRange) []portRange {
	if mode != config.NetworkModeAllowlist {
		return ports
	}
	var out []portRange
	for _, r := range ports {
		out = append(out, splitOutPorts(r, 53, 853)...)
	}
	return out
}

// splitOutPorts returns r without the given ports (ascending).
func splitOutPorts(r portRange, ports ...uint16) []portRange {
	out := []portRange{r}
	for _, p := range ports {
		var next []portRange
		for _, c := range out {
			if p < c.Lo || p > c.Hi {
				next = append(next, c)
				continue
			}
			if p > c.Lo {
				next = append(next, portRange{Lo: c.Lo, Hi: p - 1})
			}
			if p < c.Hi {
				next = append(next, portRange{Lo: p + 1, Hi: c.Hi})
			}
		}
		out = next
	}
	return out
}

// allowlistHostAccepts returns the allowed_domains literal entries that name a
// host address, each on its own ports (else the global allowed_ports). An
// entry with neither opens nothing on the host.
func allowlistHostAccepts(tuples []staticTuple, globalPorts []portRange, hostAddrs map[string]bool) []hostPortAccept {
	var accepts []hostPortAccept
	for _, t := range tuples {
		ip := strings.TrimSuffix(t.CIDR, "/32")
		if !hostAddrs[ip] {
			continue
		}
		ports := t.Ports
		if len(ports) == 0 {
			ports = globalPorts
		}
		ports = hostAcceptPorts(config.NetworkModeAllowlist, ports)
		if len(ports) == 0 {
			logWarnf("Warning: allowed_domains entry %s is an address of this host; give it ports (or set allowed_ports) to reach it, or set network.allow_host_access", ip)
			continue
		}
		accepts = append(accepts, hostPortAccept{IP: ip, Ports: ports})
	}
	return accepts
}

// addHostInputRules adds the container's input-chain rules for mode
// (restricted or allowlist), to the current batch if there is one. A no-op
// with allow_host_access.
func (f *NftManager) addHostInputRules(cfg *config.NetworkConfig, mode config.NetworkMode, accepts []hostPortAccept) error {
	if f.containerIP == "" || config.BoolVal(cfg.AllowHostAccess) {
		return nil
	}
	cmds := hostInputRuleCmds(f.containerIP, f.gatewayIP, mode, accepts)
	if f.batch != nil {
		f.batch = append(f.batch, cmds...)
		return nil
	}
	if err := ensureCOIInputChain(); err != nil {
		return err
	}
	for _, c := range cmds {
		if _, err := runNFTCommand(c...); err != nil {
			return fmt.Errorf("nft host input rule add failed: %w", err)
		}
	}
	return nil
}

// insertHostAccept prepends an accept for a host address to the coi input
// chain, ahead of the container's reject. Used for [[network.hosts]] entries,
// which are applied after the mode's rules.
func insertHostAccept(containerIP string, a hostPortAccept) error {
	if err := ensureCOIInputChain(); err != nil {
		return err
	}
	args := []string{"insert", "rule", "ip", "coi", "input", "ip", "saddr", containerIP}
	args = append(args, hostAcceptMatch(a)...)
	args = append(args, "comment", fmt.Sprintf(`"coi-%s"`, containerIP))
	if _, err := runNFTCommand(args...); err != nil {
		return fmt.Errorf("nft insert host accept rule failed: %w", err)
	}
	return nil
}

// deleteInputRuleCmds lists the coi input chain rules carrying comment as
// `delete rule` commands. A missing chain holds no rules.
func deleteInputRuleCmds(comment string) ([][]string, error) {
	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "input")
	if err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return nil, nil
		}
		return nil, err
	}
	return deleteChainRuleCmds("input", parseChainRules(string(output), comment)), nil
}

// deleteChainRuleCmds turns rules of an ip coi chain into `delete rule`
// commands.
func deleteChainRuleCmds(chain string, rules []chainRule) [][]string {
	cmds := make([][]string, 0, len(rules))
	for _, r := range rules {
		cmds = append(cmds, []string{"delete", "rule", "ip", "coi", chain, "handle", r.handle})
	}
	return cmds
}

// coiChainRules lists the ip coi table in one nft call and returns, per
// chain, the rules carrying comment, plus the chains the table has. A missing
// table holds nothing.
func coiChainRules(comment string) (rules map[string][]chainRule, chains map[string]bool, err error) {
	output, err := runNFTCommand("-a", "list", "table", "ip", "coi")
	if err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return map[string][]chainRule{}, map[string]bool{}, nil
		}
		return nil, nil, err
	}
	rules, chains = parseCOIChainRules(string(output), comment)
	return rules, chains, nil
}

// parseCOIChainRules splits an `nft -a list table` listing by chain. Pure, for
// testing.
func parseCOIChainRules(listing, comment string) (rules map[string][]chainRule, chains map[string]bool) {
	rules = make(map[string][]chainRule)
	chains = make(map[string]bool)
	sections := make(map[string]*strings.Builder)
	current := ""
	for _, line := range strings.Split(listing, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "chain "):
			current = strings.Fields(trimmed)[1]
			chains[current] = true
			sections[current] = &strings.Builder{}
		case strings.HasPrefix(trimmed, "set ") || strings.HasPrefix(trimmed, "map ") || trimmed == "}":
			current = ""
		case current != "":
			sections[current].WriteString(line + "\n")
		}
	}
	for chain, b := range sections {
		if r := parseChainRules(b.String(), comment); len(r) > 0 {
			rules[chain] = r
		}
	}
	return rules, chains
}
