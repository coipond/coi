package network

import (
	"net"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// Shapes captured from `nft -j list chain` / `nft -j list set` (nft 1.0.9).
const (
	saddrMatch   = `{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.2.3"}}`
	l4TCPUDP     = `{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}}`
	rejectVerdct = `{"reject": {"type": "icmp", "expr": "port-unreachable"}}`
)

func chainJSON(rules ...string) []byte {
	out := `{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
 {"chain": {"family": "ip", "table": "coi", "name": "forward", "handle": 1}}`
	for _, r := range rules {
		out += ",\n" + r
	}
	return []byte(out + "]}")
}

func rule(comment string, exprs ...string) string {
	body := ""
	for i, e := range exprs {
		if i > 0 {
			body += ", "
		}
		body += e
	}
	return `{"rule": {"family": "ip", "table": "coi", "chain": "forward", "handle": 1, "comment": "` + comment + `", "expr": [` + body + `]}}`
}

func daddr(right string) string {
	return `{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": ` + right + `}}`
}

func dport(proto, right string) string {
	return `{"match": {"op": "==", "left": {"payload": {"protocol": "` + proto + `", "field": "dport"}}, "right": ` + right + `}}`
}

// A realistic allowlist chain: targeted LAN host accept (inserted first), DHCP
// (udp only) to the gateway, pinned DNS, port-scoped set lookup, ICMP set accept
// (unknown accept, skipped), RFC1918 rejects, default reject — plus another
// container's rule that must be ignored.
var allowlistChain = chainJSON(
	rule("coi-10.1.2.3", saddrMatch, daddr(`"192.168.1.20"`), l4TCPUDP,
		dport("th", `{"set": [443, {"range": [8000, 8010]}]}`), `{"accept": null}`),
	rule("coi-10.1.2.3", saddrMatch, daddr(`"10.1.2.1"`), dport("udp", `{"set": [67, 68]}`), `{"accept": null}`),
	rule("coi-10.1.2.3", saddrMatch, daddr(`"10.50.0.53"`), l4TCPUDP, dport("th", `53`), `{"accept": null}`),
	rule("coi-10.1.2.3", saddrMatch, l4TCPUDP, dport("th", `53`), rejectVerdct),
	rule("coi-10.1.2.3", saddrMatch, l4TCPUDP,
		`{"match": {"op": "==", "left": {"concat": [{"payload": {"protocol": "ip", "field": "daddr"}}, {"payload": {"protocol": "th", "field": "dport"}}]}, "right": "@coi_sp_10_1_2_3"}}`,
		`{"accept": null}`),
	rule("coi-10.1.2.3", saddrMatch, daddr(`"@coi_s_10_1_2_3"`),
		`{"match": {"op": "==", "left": {"payload": {"protocol": "icmp", "field": "type"}}, "right": "echo-request"}}`,
		`{"limit": {"rate": 10, "per": "second"}}`, `{"accept": null}`),
	rule("coi-10.1.2.3", saddrMatch, daddr(`{"prefix": {"addr": "192.168.0.0", "len": 16}}`), rejectVerdct),
	rule("coi-10.1.2.3", saddrMatch, daddr(`{"prefix": {"addr": "10.0.0.0", "len": 8}}`), rejectVerdct),
	rule("coi-10.1.2.3", saddrMatch, rejectVerdct),
	rule("coi-10.1.2.30", `{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.2.30"}}`,
		daddr(`{"prefix": {"addr": "192.168.0.0", "len": 16}}`), `{"accept": null}`),
)

const sampleTupleSet = `{"nftables": [{"metainfo": {"version": "1.0.9"}}, {"set": {"family": "ip", "name": "coi_sp_10_1_2_3", "table": "coi",
 "elem": [{"concat": ["140.82.112.3", 443]},
          {"concat": [{"prefix": {"addr": "10.9.0.0", "len": 16}}, {"range": [8000, 8010]}]},
          {"elem": {"val": {"concat": ["1.2.3.4", 443]}, "timeout": 3600, "expires": 3599}}]}}]}`

type permitCase struct {
	proto string
	ip    string
	port  int
	want  bool
}

func checkPermits(t *testing.T, rules []egressRule, cases []permitCase) {
	t.Helper()
	for _, tc := range cases {
		if got := firstMatchPermits(rules, tc.proto, net.ParseIP(tc.ip).To4(), tc.port); got != tc.want {
			t.Errorf("%s %s:%d permitted=%v, want %v", tc.proto, tc.ip, tc.port, got, tc.want)
		}
	}
}

func TestParseContainerEgressRules_FirstMatch(t *testing.T) {
	rules, err := parseContainerEgressRules(allowlistChain, "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 8 { // ICMP set rule skipped, other container ignored
		t.Fatalf("want 8 rules, got %d", len(rules))
	}
	tuples, err := parseNftTupleSet([]byte(sampleTupleSet))
	if err != nil {
		t.Fatal(err)
	}
	if len(tuples) != 3 {
		t.Fatalf("want 3 tuples, got %d", len(tuples))
	}
	rules[4].tuples = tuples
	checkPermits(t, rules, []permitCase{
		{"tcp", "192.168.1.20", 443, true},
		{"udp", "192.168.1.20", 8005, true},
		{"tcp", "192.168.1.20", 22, false}, // other port on the host: RFC1918 reject
		{"tcp", "192.168.1.21", 443, false},
		{"udp", "10.1.2.1", 67, true},
		{"tcp", "10.1.2.1", 67, false},  // DHCP rule is udp only
		{"udp", "10.50.0.53", 53, true}, // pinned LAN resolver
		{"udp", "10.50.0.54", 53, false},
		{"tcp", "140.82.112.3", 443, true}, // allowlist set tuple
		{"tcp", "140.82.112.3", 22, false},
		{"tcp", "10.9.4.4", 8001, true}, // CIDR . range tuple
		{"tcp", "1.2.3.4", 443, true},   // timeout-wrapped (runtime) element
		{"tcp", "8.8.8.8", 443, false},  // default reject
		{"icmp", "192.168.1.20", 0, false},
	})
}

// An unparsed reject ends evaluation as "not permitted", so a later broad accept
// can never exempt traffic the firewall rejects; an unparsed accept is skipped.
func TestParseContainerEgressRules_UnknownRules(t *testing.T) {
	chain := chainJSON(
		rule("coi-10.1.2.3", saddrMatch,
			`{"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}}`,
			rejectVerdct),
		rule("coi-10.1.2.3", saddrMatch, `{"accept": null}`),
	)
	rules, err := parseContainerEgressRules(chain, "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	checkPermits(t, rules, []permitCase{{"tcp", "10.5.5.5", 22, false}, {"tcp", "8.8.8.8", 443, false}})

	chain = chainJSON(
		rule("coi-10.1.2.3", saddrMatch, `{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "established"}}`, `{"accept": null}`),
		rule("coi-10.1.2.3", saddrMatch, daddr(`{"prefix": {"addr": "10.0.0.0", "len": 8}}`), rejectVerdct),
		rule("coi-10.1.2.3", saddrMatch, `{"accept": null}`),
	)
	if rules, err = parseContainerEgressRules(chain, "10.1.2.3"); err != nil {
		t.Fatal(err)
	}
	checkPermits(t, rules, []permitCase{{"tcp", "10.5.5.5", 22, false}, {"tcp", "8.8.8.8", 443, true}})
}

func TestLocalAccessFromRules(t *testing.T) {
	for ip, want := range map[string]bool{"10.1.2.3": false, "10.1.2.30": true} {
		rules, err := parseContainerEgressRules(allowlistChain, ip)
		if err != nil {
			t.Fatal(err)
		}
		on, ok := localAccessFromRules(rules)
		if !ok || on != want {
			t.Errorf("%s: local access on=%v ok=%v, want on=%v", ip, on, ok, want)
		}
	}
	if _, ok := localAccessFromRules(nil); ok {
		t.Error("no rules must report unknown")
	}
}

// Live rules are authoritative once read: a configured host the running
// container's chain rejects is not permitted. Before a read, the configured
// hosts answer.
func TestEgressPermits_LiveRulesAuthoritative(t *testing.T) {
	hosts := []config.HostEntry{{IP: "10.0.0.5", Hostnames: []string{"stale"}}}
	p := NewEgressPermits("10.1.2.3", hosts, nil)
	if !p.Permits("TCP", "10.0.0.5", 22) {
		t.Fatal("before any read, the configured host should be permitted")
	}
	rules, err := parseContainerEgressRules(allowlistChain, "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	p.rules = rules
	if p.Permits("tcp", "10.0.0.5", 22) {
		t.Error("a host the live chain rejects must not be permitted from config")
	}
	if !p.Permits("tcp6", "192.168.1.20", 443) {
		t.Error("tcp6 should be treated as tcp")
	}
}

func TestHostEntriesPermit(t *testing.T) {
	hosts := []config.HostEntry{
		{IP: "10.50.0.100", Hostnames: []string{"redmine"}, Ports: []int{443}},
		{IP: "10.50.0.200", Hostnames: []string{"nas"}},
	}
	for _, tc := range []struct {
		proto   string
		ip      string
		port    int
		allowed []int
		want    bool
	}{
		{"tcp", "10.50.0.100", 443, nil, true},
		{"tcp", "10.50.0.100", 22, nil, false},
		{"tcp", "10.50.0.200", 22, nil, true},         // no ports anywhere: all ports
		{"tcp", "10.50.0.200", 22, []int{443}, false}, // inherits allowed_ports
		{"udp", "10.50.0.200", 443, []int{443}, true},
		{"icmp", "10.50.0.200", 0, nil, false},
		{"tcp", "10.50.0.1", 443, nil, false},
	} {
		if got := hostEntriesPermit(hosts, tc.allowed, tc.proto, net.ParseIP(tc.ip).To4(), tc.port); got != tc.want {
			t.Errorf("%s %s:%d allowed=%v permitted=%v, want %v", tc.proto, tc.ip, tc.port, tc.allowed, got, tc.want)
		}
	}
}
