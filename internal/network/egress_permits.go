package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coipond/coi/internal/config"
)

// portRangeIncl is an inclusive destination-port range.
type portRangeIncl [2]int

// egressTuple is one (destination . port-range) element of a port-scoped set.
type egressTuple struct {
	dst   *net.IPNet
	ports portRangeIncl
}

// egressRule is one per-container rule of the coi forward chain, reduced to what
// decides a TCP/UDP destination. A nil dst, ports or protos means "any".
type egressRule struct {
	dst    *net.IPNet
	ports  []portRangeIncl
	protos map[string]bool // "tcp" / "udp"
	// set names a concatenated `ip daddr . th dport @set` lookup; tuples holds
	// its elements, read when the rules are refreshed.
	set    string
	tuples []egressTuple
	accept bool
}

func (r egressRule) matches(proto string, ip net.IP, port int) bool {
	if r.protos != nil && !r.protos[proto] {
		return false
	}
	if r.dst != nil && !r.dst.Contains(ip) {
		return false
	}
	if r.ports != nil && !portIn(r.ports, port) {
		return false
	}
	if r.set != "" {
		for _, t := range r.tuples {
			if t.dst.Contains(ip) && port >= t.ports[0] && port <= t.ports[1] {
				return true
			}
		}
		return false
	}
	return true
}

func portIn(ranges []portRangeIncl, port int) bool {
	for _, pr := range ranges {
		if port >= pr[0] && port <= pr[1] {
			return true
		}
	}
	return false
}

// firstMatchPermits evaluates rules in chain order and reports whether the first
// rule matching proto ip:port accepts. No match means the firewall does not
// permit it (every enforcing mode ends in a default reject).
func firstMatchPermits(rules []egressRule, proto string, ip net.IP, port int) bool {
	for _, r := range rules {
		if r.matches(proto, ip, port) {
			return r.accept
		}
	}
	return false
}

// parseContainerEgressRules extracts, in order, the containerIP's rules from
// `nft -j list chain ip coi forward`.
//
// A rule the parser does not fully understand cannot be evaluated, and is
// handled so the answer can only err towards "not permitted" (an alert), never
// towards exempting traffic the firewall blocks: an unknown ACCEPT (ICMP, an
// address-only set lookup) is skipped, while an unknown REJECT/DROP becomes a
// match-everything reject that ends evaluation there.
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
		r, ok, accepts := parseEgressRule(item.Rule.Expr, containerIP)
		switch {
		case ok:
			rules = append(rules, r)
		case !accepts:
			rules = append(rules, egressRule{}) // unknown reject/drop: stop here
		}
	}
	return rules, nil
}

// parseEgressRule returns the rule, whether it was fully understood, and whether
// its verdict is accept (used for a rule that was not understood).
func parseEgressRule(exprs []json.RawMessage, containerIP string) (r egressRule, ok, accepts bool) {
	sawSaddr, sawVerdict, understood := false, false, true
	for _, raw := range exprs {
		var e map[string]json.RawMessage
		if err := json.Unmarshal(raw, &e); err != nil || len(e) != 1 {
			understood = false
			continue
		}
		switch {
		case e["accept"] != nil:
			r.accept, sawVerdict, accepts = true, true, true
		case e["reject"] != nil, e["drop"] != nil:
			sawVerdict = true
		case e["counter"] != nil, e["log"] != nil:
			// no effect on the verdict
		case e["match"] != nil:
			if !parseEgressMatch(e["match"], containerIP, &r, &sawSaddr) {
				understood = false
			}
		default:
			understood = false
		}
	}
	return r, understood && sawSaddr && sawVerdict, accepts
}

type nftPayload struct{ Protocol, Field string }

func parseEgressMatch(raw json.RawMessage, containerIP string, r *egressRule, sawSaddr *bool) bool {
	var m struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if json.Unmarshal(raw, &m) != nil || m.Op != "==" {
		return false
	}
	var left struct {
		Payload *nftPayload           `json:"payload"`
		Meta    *struct{ Key string } `json:"meta"`
		Concat  []struct {
			Payload *nftPayload `json:"payload"`
		} `json:"concat"`
	}
	if json.Unmarshal(m.Left, &left) != nil {
		return false
	}
	switch {
	case left.Payload != nil && *left.Payload == nftPayload{"ip", "saddr"}:
		var s string
		if json.Unmarshal(m.Right, &s) != nil || s != containerIP {
			return false
		}
		*sawSaddr = true
	case left.Payload != nil && *left.Payload == nftPayload{"ip", "daddr"}:
		dst, ok := parseNftAddr(m.Right)
		if !ok {
			return false
		}
		r.dst = dst
	case left.Payload != nil && left.Payload.Field == "dport":
		ports, ok := parseNftPorts(m.Right)
		if !ok {
			return false
		}
		r.ports = ports
		switch left.Payload.Protocol {
		case "th":
		case "tcp", "udp":
			restrictProtos(r, []string{left.Payload.Protocol})
		default:
			return false
		}
	case left.Meta != nil && left.Meta.Key == "l4proto":
		names, ok := parseNftNames(m.Right)
		if !ok {
			return false
		}
		restrictProtos(r, names)
	case len(left.Concat) == 2 && left.Concat[0].Payload != nil && left.Concat[1].Payload != nil &&
		*left.Concat[0].Payload == nftPayload{"ip", "daddr"} && left.Concat[1].Payload.Field == "dport":
		var s string
		if json.Unmarshal(m.Right, &s) != nil || !strings.HasPrefix(s, "@") {
			return false
		}
		r.set = s[1:]
	default:
		return false
	}
	return true
}

// restrictProtos narrows the rule's protocols to names, intersecting with any
// earlier restriction.
func restrictProtos(r *egressRule, names []string) {
	next := make(map[string]bool, len(names))
	for _, n := range names {
		if r.protos == nil || r.protos[n] {
			next[n] = true
		}
	}
	r.protos = next
}

// parseNftNames reads "udp" or {"set":["tcp","udp"]}.
func parseNftNames(raw json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, true
	}
	var set struct {
		Set []string `json:"set"`
	}
	if json.Unmarshal(raw, &set) != nil || set.Set == nil {
		return nil, false
	}
	return set.Set, true
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

// parseNftPorts reads an nft JSON port match: 443, {"range":[a,b]} or a set of
// either.
func parseNftPorts(raw json.RawMessage) ([]portRangeIncl, bool) {
	var one int
	if json.Unmarshal(raw, &one) == nil {
		return []portRangeIncl{{one, one}}, true
	}
	var rng struct {
		Range []int `json:"range"`
	}
	if json.Unmarshal(raw, &rng) == nil && len(rng.Range) == 2 {
		return []portRangeIncl{{rng.Range[0], rng.Range[1]}}, true
	}
	var set struct {
		Set []json.RawMessage `json:"set"`
	}
	if json.Unmarshal(raw, &set) != nil || set.Set == nil {
		return nil, false
	}
	var out []portRangeIncl
	for _, el := range set.Set {
		prs, ok := parseNftPorts(el)
		if !ok {
			return nil, false
		}
		out = append(out, prs...)
	}
	return out, true
}

// parseNftTupleSet reads the (address . port) elements of `nft -j list set` on a
// concatenated set, including timeout-wrapped elements. An element it cannot
// read is skipped, which can only make a destination look not permitted.
func parseNftTupleSet(output []byte) ([]egressTuple, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse nft set JSON: %w", err)
	}
	var out []egressTuple
	for _, obj := range doc.Nftables {
		if obj.Set == nil {
			continue
		}
		for _, raw := range obj.Set.Elem {
			var el struct {
				Concat []json.RawMessage `json:"concat"`
				Elem   *struct {
					Val struct {
						Concat []json.RawMessage `json:"concat"`
					} `json:"val"`
				} `json:"elem"`
			}
			if json.Unmarshal(raw, &el) != nil {
				continue
			}
			parts := el.Concat
			if el.Elem != nil {
				parts = el.Elem.Val.Concat
			}
			if len(parts) != 2 {
				continue
			}
			dst, ok := parseNftAddr(parts[0])
			ports, pok := parseNftPorts(parts[1])
			if !ok || !pok || len(ports) != 1 {
				continue
			}
			out = append(out, egressTuple{dst: dst, ports: ports[0]})
		}
	}
	return out, nil
}

// readContainerEgressRules lists the coi forward chain and returns containerIP's
// rules, with the elements of any port-scoped set lookup filled in.
func readContainerEgressRules(containerIP string) ([]egressRule, error) {
	output, err := runNFTCommand("-j", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		return nil, err
	}
	rules, err := parseContainerEgressRules(output, containerIP)
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].set == "" {
			continue
		}
		out, err := runNFTCommand("-j", "list", "set", "ip", "coi", rules[i].set)
		if err != nil {
			if isNftNotFound(err) {
				continue
			}
			return nil, err
		}
		if rules[i].tuples, err = parseNftTupleSet(out); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

// containerLocalNetworkAccess reports whether an allowlist container was launched
// with allow_local_network_access, from its live rules: allowlist mode emits a
// 192.168.0.0/16 accept when local access is on and a reject when it is off.
// ok is false when neither is found (rules unreadable, or not allowlist mode).
func containerLocalNetworkAccess(containerIP string) (on, ok bool) {
	output, err := runNFTCommand("-j", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		return false, false
	}
	rules, err := parseContainerEgressRules(output, containerIP)
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
// service, a host added at runtime with `coi hosts add`, a pinned LAN resolver
// on :53, or the LAN under allow_local_network_access — must not be reported.
//
// The answer comes from the container's live nft rules (first match, protocol-
// and port-aware, including the allowlist's port-scoped sets), so it tracks
// runtime changes and a blocked probe of another port on the same host is still
// flagged. The rules are re-read in the background (Start), so Permits never
// blocks a monitor on nft. Until they have been read — or if they cannot be read,
// or hold nothing for this container — the configured host entries answer
// instead: each on its own ports, else the global allowed_ports, else all ports.
type EgressPermits struct {
	containerIP  string
	hosts        []config.HostEntry
	allowedPorts []int

	mu    sync.RWMutex
	rules []egressRule // nil until a read returned rules for this container
}

// NewEgressPermits creates the permit checker for a container.
func NewEgressPermits(containerIP string, hosts []config.HostEntry, allowedPorts []int) *EgressPermits {
	return &EgressPermits{containerIP: containerIP, hosts: hosts, allowedPorts: allowedPorts}
}

// Start reads the rules now and then every interval until ctx is done.
func (p *EgressPermits) Start(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			p.refresh()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (p *EgressPermits) refresh() {
	rules, err := readContainerEgressRules(p.containerIP)
	if err != nil || len(rules) == 0 {
		return // keep the last good snapshot (or the configured hosts)
	}
	p.mu.Lock()
	p.rules = rules
	p.mu.Unlock()
}

// Permits reports whether the firewall accepts proto ("tcp"/"udp", any case;
// "tcp6"/"udp6" too) traffic to ip:port.
func (p *EgressPermits) Permits(proto, ipStr string, port int) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	proto = strings.TrimSuffix(strings.ToLower(proto), "6")
	p.mu.RLock()
	rules := p.rules
	p.mu.RUnlock()
	if rules != nil {
		return firstMatchPermits(rules, proto, ip, port)
	}
	return hostEntriesPermit(p.hosts, p.allowedPorts, proto, ip, port)
}

func hostEntriesPermit(hosts []config.HostEntry, allowedPorts []int, proto string, ip net.IP, port int) bool {
	if proto != "tcp" && proto != "udp" {
		return false
	}
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
