package network

import (
	"net"
	"strings"

	"github.com/coipond/coi/internal/config"
)

// ExplicitPortPermits answers "did the user name this exact port for this
// destination?" for the monitors' suspicious-port check. Unlike EgressPermits it
// ignores inherited ports: only a [[network.hosts]] entry with its own ports, or
// an allowed_domains entry with a :ports suffix, counts. A host entry without
// ports, the global allowed_ports and allow_local_network_access do not.
type ExplicitPortPermits struct {
	entries []explicitPortPermit
}

type explicitPortPermit struct {
	dst   *net.IPNet
	ports []portRange
}

// NewExplicitPortPermits collects the explicit port permits from the
// [[network.hosts]] entries and, in allowlist mode, from the compiled
// allowed_domains policy (nil otherwise). resolved maps each policy name to the
// addresses the monitor resolved for it; a name missing there permits nothing.
func NewExplicitPortPermits(hosts []config.HostEntry, policy *AllowPolicy, resolved map[string][]string) *ExplicitPortPermits {
	p := &ExplicitPortPermits{}
	for _, h := range hosts {
		if len(h.Ports) == 0 {
			continue
		}
		if dst := parseHostOrCIDR(h.IP); dst != nil {
			p.entries = append(p.entries, explicitPortPermit{dst: dst, ports: intsToPortRanges(h.Ports)})
		}
	}
	if policy == nil {
		return p
	}
	for _, t := range policy.staticTuples() {
		if len(t.Ports) == 0 {
			continue
		}
		if dst := parseHostOrCIDR(t.CIDR); dst != nil {
			p.entries = append(p.entries, explicitPortPermit{dst: dst, ports: t.Ports})
		}
	}
	for _, name := range policy.Names() {
		ports := policy.portsForName(name)
		if len(ports) == 0 {
			continue
		}
		for _, addr := range resolved[name] {
			if dst := parseHostOrCIDR(addr); dst != nil {
				p.entries = append(p.entries, explicitPortPermit{dst: dst, ports: ports})
			}
		}
	}
	return p
}

// Permits reports whether proto ("tcp"/"udp", any case; "tcp6"/"udp6" too)
// traffic to ip:port has an explicit port permit.
func (p *ExplicitPortPermits) Permits(proto, ipStr string, port int) bool {
	proto = strings.TrimSuffix(strings.ToLower(proto), "6")
	if proto != "tcp" && proto != "udp" {
		return false
	}
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	for _, e := range p.entries {
		if !e.dst.Contains(ip) {
			continue
		}
		for _, r := range e.ports {
			if port >= int(r.Lo) && port <= int(r.Hi) {
				return true
			}
		}
	}
	return false
}

// parseHostOrCIDR reads an IPv4 address (as a /32) or an IPv4 CIDR.
func parseHostOrCIDR(s string) *net.IPNet {
	if strings.Contains(s, "/") {
		ip, n, err := net.ParseCIDR(s)
		if err != nil || ip.To4() == nil {
			return nil
		}
		return n
	}
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
}
