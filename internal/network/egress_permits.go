package network

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/coipond/coi/internal/config"
)

// egressRule is one per-container rule of the coi forward chain, reduced to what
// decides a TCP/UDP destination: the destination network (nil = any), the
// destination ports (nil = any) and whether it accepts.
type egressRule struct {
	dst    *net.IPNet
	ports  [][2]int // inclusive ranges
	accept bool
}

func (r egressRule) matches(ip net.IP, port int) bool {
	if r.dst != nil && !r.dst.Contains(ip) {
		return false
	}
	if r.ports == nil {
		return true
	}
	for _, pr := range r.ports {
		if port >= pr[0] && port <= pr[1] {
			return true
		}
	}
	return false
}

// firstMatchPermits evaluates rules in chain order and reports whether the first
// rule matching ip:port accepts. No match means the firewall does not permit it.
func firstMatchPermits(rules []egressRule, ip net.IP, port int) bool {
	for _, r := range rules {
		if r.matches(ip, port) {
			return r.accept
		}
	}
	return false
}

// parseContainerEgressRules extracts, in order, the containerIP's rules from
// `nft -j list chain ip coi forward`. Only rules the parser fully understands
// (saddr, an address or prefix daddr, an l4proto and/or a dport match, then an
// accept/reject/drop verdict) are kept; anything else — set lookups, ICMP, ct
// state — is skipped. A skipped rule can only make the answer less precise for
// the monitor (a blocked attempt reported as permitted is merely not alerted on);
// it never changes what the firewall enforces.
func parseContainerEgressRules(output []byte, containerIP string) ([]egressRule, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse nft chain JSON: %w", err)
	}
	comment := "coi-" + containerIP
	var rules []egressRule
	for _, item := range doc.Nftables {
		if item.Rule == nil || item.Rule.Comment != comment {
			continue
		}
		if r, ok := parseEgressRule(item.Rule.Expr, containerIP); ok {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func parseEgressRule(exprs []json.RawMessage, containerIP string) (egressRule, bool) {
	var r egressRule
	sawSaddr, sawVerdict := false, false
	for _, raw := range exprs {
		var e map[string]json.RawMessage
		if err := json.Unmarshal(raw, &e); err != nil || len(e) != 1 {
			return r, false
		}
		switch {
		case e["accept"] != nil:
			r.accept, sawVerdict = true, true
		case e["reject"] != nil, e["drop"] != nil:
			sawVerdict = true
		case e["match"] != nil:
			var m struct {
				Op    string          `json:"op"`
				Left  json.RawMessage `json:"left"`
				Right json.RawMessage `json:"right"`
			}
			if json.Unmarshal(e["match"], &m) != nil || (m.Op != "==" && m.Op != "in") {
				return r, false
			}
			var left struct {
				Payload *struct{ Protocol, Field string } `json:"payload"`
				Meta    *struct{ Key string }             `json:"meta"`
			}
			if json.Unmarshal(m.Left, &left) != nil {
				return r, false
			}
			switch {
			case left.Payload != nil && left.Payload.Protocol == "ip" && left.Payload.Field == "saddr":
				var s string
				if json.Unmarshal(m.Right, &s) != nil || s != containerIP {
					return r, false
				}
				sawSaddr = true
			case left.Payload != nil && left.Payload.Protocol == "ip" && left.Payload.Field == "daddr":
				dst, ok := parseNftAddr(m.Right)
				if !ok {
					return r, false
				}
				r.dst = dst
			case left.Payload != nil && left.Payload.Field == "dport":
				ports, ok := parseNftPorts(m.Right)
				if !ok {
					return r, false
				}
				r.ports = ports
			case left.Meta != nil && left.Meta.Key == "l4proto":
				// tcp/udp only; the monitors ask about TCP/UDP destinations.
			default:
				return r, false
			}
		default:
			// counter, log, etc. do not affect the verdict; anything else is unknown.
			if e["counter"] == nil && e["log"] == nil {
				return r, false
			}
		}
	}
	return r, sawSaddr && sawVerdict
}

// parseNftAddr reads an nft JSON address: "1.2.3.4" or {"prefix":{"addr","len"}}.
func parseNftAddr(raw json.RawMessage) (*net.IPNet, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			return nil, false
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, true
	}
	var p struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(raw, &p) != nil || p.Prefix == nil {
		return nil, false
	}
	_, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", p.Prefix.Addr, p.Prefix.Len))
	if err != nil {
		return nil, false
	}
	return n, true
}

// parseNftPorts reads an nft JSON port match: 443, {"set":[443, {"range":[8000,8010]}]}
// or {"range":[a,b]}.
func parseNftPorts(raw json.RawMessage) ([][2]int, bool) {
	var one int
	if json.Unmarshal(raw, &one) == nil {
		return [][2]int{{one, one}}, true
	}
	var rng struct {
		Range []int `json:"range"`
	}
	if json.Unmarshal(raw, &rng) == nil && len(rng.Range) == 2 {
		return [][2]int{{rng.Range[0], rng.Range[1]}}, true
	}
	var set struct {
		Set []json.RawMessage `json:"set"`
	}
	if json.Unmarshal(raw, &set) != nil || set.Set == nil {
		return nil, false
	}
	var out [][2]int
	for _, el := range set.Set {
		prs, ok := parseNftPorts(el)
		if !ok {
			return nil, false
		}
		out = append(out, prs...)
	}
	return out, true
}

// readContainerEgressRules lists the coi forward chain and returns containerIP's rules.
func readContainerEgressRules(containerIP string) ([]egressRule, error) {
	output, err := runNFTCommand("-j", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		return nil, err
	}
	return parseContainerEgressRules(output, containerIP)
}

// containerLocalNetworkAccess reports whether an allowlist container was launched
// with allow_local_network_access, from its live rules: allowlist mode emits a
// 192.168.0.0/16 accept when local access is on and a reject when it is off.
// ok is false when neither is found (rules unreadable, or not allowlist mode).
func containerLocalNetworkAccess(containerIP string) (on, ok bool) {
	rules, err := readContainerEgressRules(containerIP)
	if err != nil {
		return false, false
	}
	return localAccessFromRules(rules)
}

func localAccessFromRules(rules []egressRule) (on, ok bool) {
	for _, r := range rules {
		if r.dst != nil && r.dst.String() == "192.168.0.0/16" {
			return r.accept, true
		}
	}
	return false, false
}

// EgressPermits answers "does this container's firewall let it reach ip:port?"
// for the security monitors. They flag private-network (and, in allowlist mode,
// non-allowlisted) connections because the firewall is supposed to block them;
// a destination the firewall deliberately accepts — a [[network.hosts]] LAN
// service, one added at runtime with `coi hosts add`, a pinned LAN resolver on
// :53, or the LAN under allow_local_network_access — must not be reported as one.
//
// The answer comes from the container's live nft rules (first match, port-aware),
// so it tracks runtime changes, and a blocked probe to another port on the same
// host is still flagged. The rules are re-read at most once per ttl. The
// configured host entries (each on its own ports, else the global allowed_ports,
// else all ports) count as well: they were applied at launch, and an allowlist
// mode public entry is accepted through a set lookup the rule parser skips. They
// are also the whole answer when the rules cannot be read.
type EgressPermits struct {
	containerName string
	hosts         []config.HostEntry
	allowedPorts  []int
	ttl           time.Duration

	mu        sync.Mutex
	ip        string
	rules     []egressRule
	haveRules bool
	fetched   time.Time
}

// NewEgressPermits creates the permit checker for a container. The container IP
// is resolved lazily, so it can be built before the container has its lease.
func NewEgressPermits(containerName string, hosts []config.HostEntry, allowedPorts []int) *EgressPermits {
	return &EgressPermits{containerName: containerName, hosts: hosts, allowedPorts: allowedPorts, ttl: 5 * time.Second}
}

// Permits reports whether the firewall accepts TCP/UDP traffic to ip:port.
func (p *EgressPermits) Permits(ipStr string, port int) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshLocked()
	if p.haveRules && firstMatchPermits(p.rules, ip, port) {
		return true
	}
	return hostEntriesPermit(p.hosts, p.allowedPorts, ip, port)
}

func (p *EgressPermits) refreshLocked() {
	if !p.fetched.IsZero() && time.Since(p.fetched) < p.ttl {
		return
	}
	p.fetched = time.Now()
	if p.ip == "" {
		ip, err := GetContainerIP(p.containerName)
		if err != nil || ip == "" {
			return
		}
		p.ip = ip
	}
	rules, err := readContainerEgressRules(p.ip)
	if err != nil {
		return // keep the last good snapshot (or the config fallback)
	}
	p.rules, p.haveRules = rules, true
}

func hostEntriesPermit(hosts []config.HostEntry, allowedPorts []int, ip net.IP, port int) bool {
	for _, h := range hosts {
		if !net.ParseIP(h.IP).Equal(ip) {
			continue
		}
		ports := h.Ports
		if len(ports) == 0 {
			ports = allowedPorts
		}
		if len(ports) == 0 {
			return true
		}
		for _, p := range ports {
			if p == port {
				return true
			}
		}
	}
	return false
}
