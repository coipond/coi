package network

import (
	"net"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// Captured from `nft -j list chain ip coi forward` (nft 1.0.9): a targeted
// host-entry accept, a pinned DNS accept + reject, an allowlist set lookup (not
// understood, skipped), RFC1918 rejects, and another container's rule.
const sampleForwardChain = `{"nftables": [
 {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
 {"chain": {"family": "ip", "table": "coi", "name": "forward", "handle": 1}},
 {"rule": {"family": "ip", "table": "coi", "chain": "forward", "handle": 9, "comment": "coi-10.1.2.3", "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.2.3"}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "192.168.1.20"}},
   {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": {"set": [443, {"range": [8000, 8010]}]}}},
   {"accept": null}]}},
 {"rule": {"family": "ip", "table": "coi", "chain": "forward", "handle": 10, "comment": "coi-10.1.2.3", "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.2.3"}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "10.50.0.53"}},
   {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": 53}},
   {"accept": null}]}},
 {"rule": {"family": "ip", "table": "coi", "chain": "forward", "handle": 11, "comment": "coi-10.1.2.3", "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.2.3"}},
   {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": 53}},
   {"reject": null}]}},
 {"rule": {"family": "ip", "table": "coi", "chain": "forward", "handle": 12, "comment": "coi-10.1.2.3", "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.2.3"}},
   {"match": {"op": "==", "left": {"concat": [{"payload": {"protocol": "ip", "field": "daddr"}}, {"payload": {"protocol": "th", "field": "dport"}}]}, "right": "@coi_t_10_1_2_3"}},
   {"accept": null}]}},
 {"rule": {"family": "ip", "table": "coi", "chain": "forward", "handle": 13, "comment": "coi-10.1.2.3", "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.2.3"}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "192.168.0.0", "len": 16}}}},
   {"reject": null}]}},
 {"rule": {"family": "ip", "table": "coi", "chain": "forward", "handle": 14, "comment": "coi-10.1.2.30", "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.2.30"}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "192.168.0.0", "len": 16}}}},
   {"accept": null}]}}
]}`

func TestParseContainerEgressRules_FirstMatch(t *testing.T) {
	rules, err := parseContainerEgressRules([]byte(sampleForwardChain), "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 { // set-lookup rule skipped, other container's rule ignored
		t.Fatalf("want 4 rules, got %d: %+v", len(rules), rules)
	}
	for _, tc := range []struct {
		ip   string
		port int
		want bool
	}{
		{"192.168.1.20", 443, true},
		{"192.168.1.20", 8005, true},
		{"192.168.1.20", 22, false}, // other port on the host: falls to the RFC1918 reject
		{"192.168.1.21", 443, false},
		{"10.50.0.53", 53, true}, // pinned LAN resolver
		{"10.50.0.54", 53, false},
		{"8.8.8.8", 443, false}, // no matching rule
	} {
		if got := firstMatchPermits(rules, net.ParseIP(tc.ip).To4(), tc.port); got != tc.want {
			t.Errorf("%s:%d permitted=%v, want %v", tc.ip, tc.port, got, tc.want)
		}
	}
}

func TestLocalAccessFromRules(t *testing.T) {
	for ip, want := range map[string]bool{"10.1.2.3": false, "10.1.2.30": true} {
		rules, err := parseContainerEgressRules([]byte(sampleForwardChain), ip)
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

func TestHostEntriesPermit(t *testing.T) {
	hosts := []config.HostEntry{
		{IP: "10.50.0.100", Hostnames: []string{"redmine"}, Ports: []int{443}},
		{IP: "10.50.0.200", Hostnames: []string{"nas"}},
	}
	for _, tc := range []struct {
		ip      string
		port    int
		allowed []int
		want    bool
	}{
		{"10.50.0.100", 443, nil, true},
		{"10.50.0.100", 22, nil, false},
		{"10.50.0.200", 22, nil, true},         // no ports anywhere: all ports
		{"10.50.0.200", 22, []int{443}, false}, // inherits allowed_ports
		{"10.50.0.200", 443, []int{443}, true},
		{"10.50.0.1", 443, nil, false},
	} {
		if got := hostEntriesPermit(hosts, tc.allowed, net.ParseIP(tc.ip).To4(), tc.port); got != tc.want {
			t.Errorf("%s:%d allowed=%v permitted=%v, want %v", tc.ip, tc.port, tc.allowed, got, tc.want)
		}
	}
}
