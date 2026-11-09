package network

import (
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func joinCmds(cmds [][]string) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func TestHostInputRuleCmds_Restricted(t *testing.T) {
	got := joinCmds(hostInputRuleCmds("10.0.0.2", "10.0.0.1", config.NetworkModeRestricted,
		[]hostPortAccept{{IP: "192.168.1.5", Ports: []portRange{{Lo: 8080, Hi: 8080}, {Lo: 9000, Hi: 9100}}}}))
	want := []string{
		`add rule ip coi input ip saddr 10.0.0.2 ct state established,related accept comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 ip daddr { 10.0.0.1, 255.255.255.255 } udp dport 67 accept comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 ip daddr 10.0.0.1 icmp type echo-request limit rate 10/second accept comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 ip daddr 10.0.0.1 meta l4proto { tcp, udp } th dport 53 accept comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 ip daddr 192.168.1.5 meta l4proto { tcp, udp } th dport { 8080, 9000-9100 } accept comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 meta l4proto tcp reject with tcp reset comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 reject comment "coi-10.0.0.2"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Allowlist mode adds no DNS accept: blockDNS rejects port 53 ahead of these rules.
func TestHostInputRuleCmds_AllowlistHasNoDNSAccept(t *testing.T) {
	got := joinCmds(hostInputRuleCmds("10.0.0.2", "10.0.0.1", config.NetworkModeAllowlist, nil))
	if len(got) != 5 {
		t.Fatalf("want established, DHCP, ping and the two rejects, got %v", got)
	}
	for _, r := range got {
		if strings.Contains(r, "dport 53") {
			t.Errorf("allowlist mode must not accept DNS to the host: %s", r)
		}
	}
	if !strings.HasSuffix(got[4], `reject comment "coi-10.0.0.2"`) {
		t.Errorf("last rule must be the reject, got %s", got[4])
	}
}

func TestHostInputRuleCmds_NoGateway(t *testing.T) {
	got := joinCmds(hostInputRuleCmds("10.0.0.2", "", config.NetworkModeRestricted, nil))
	want := []string{
		`add rule ip coi input ip saddr 10.0.0.2 ct state established,related accept comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 udp dport 67 accept comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 meta l4proto { tcp, udp } th dport 53 accept comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 meta l4proto tcp reject with tcp reset comment "coi-10.0.0.2"`,
		`add rule ip coi input ip saddr 10.0.0.2 reject comment "coi-10.0.0.2"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestHostAcceptPorts(t *testing.T) {
	ports := []portRange{{Lo: 50, Hi: 60}, {Lo: 853, Hi: 853}, {Lo: 443, Hi: 443}}
	if got := hostAcceptPorts(config.NetworkModeRestricted, ports); !reflect.DeepEqual(got, ports) {
		t.Errorf("restricted keeps every port, got %v", got)
	}
	want := []portRange{{Lo: 50, Hi: 52}, {Lo: 54, Hi: 60}, {Lo: 443, Hi: 443}}
	if got := hostAcceptPorts(config.NetworkModeAllowlist, ports); !reflect.DeepEqual(got, want) {
		t.Errorf("allowlist drops the DNS ports: got %v want %v", got, want)
	}
	if got := hostAcceptPorts(config.NetworkModeAllowlist, []portRange{{Lo: 53, Hi: 53}}); len(got) != 0 {
		t.Errorf("port 53 alone leaves nothing, got %v", got)
	}
}

func TestAllowlistHostAccepts(t *testing.T) {
	host := map[string]bool{"10.0.0.1": true, "192.168.1.5": true}
	tuples := []staticTuple{
		{CIDR: "10.0.0.1/32", Ports: []portRange{{Lo: 8080, Hi: 8080}}},
		{CIDR: "192.168.1.5"}, // no ports: inherits the global ones
		{CIDR: "1.2.3.4", Ports: []portRange{{Lo: 443, Hi: 443}}},      // not a host address
		{CIDR: "192.168.1.0/24", Ports: []portRange{{Lo: 22, Hi: 22}}}, // a range is not a host address
	}
	got := allowlistHostAccepts(tuples, []portRange{{Lo: 443, Hi: 443}}, host)
	want := []hostPortAccept{
		{IP: "10.0.0.1", Ports: []portRange{{Lo: 8080, Hi: 8080}}},
		{IP: "192.168.1.5", Ports: []portRange{{Lo: 443, Hi: 443}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
	if got := allowlistHostAccepts(tuples[1:2], nil, host); len(got) != 0 {
		t.Errorf("an entry without ports opens nothing on the host, got %+v", got)
	}
}

func TestAddHostInputRules(t *testing.T) {
	f := NewNftManager("10.0.0.2", "10.0.0.1")
	f.beginBatch(nil)
	if err := f.addHostInputRules(&config.NetworkConfig{}, config.NetworkModeRestricted, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.batch) != 6 || f.batch[0][4] != "input" {
		t.Errorf("batch = %v", f.batch)
	}

	on := true
	f.beginBatch(nil)
	if err := f.addHostInputRules(&config.NetworkConfig{AllowHostAccess: &on}, config.NetworkModeRestricted, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.batch) != 0 {
		t.Errorf("allow_host_access must add no input rules, got %v", f.batch)
	}
	f.abortBatch()

	// Outside a batch every rule is its own nft call.
	logPath := fakeNftSudo(t, "")
	if err := f.addHostInputRules(&config.NetworkConfig{}, config.NetworkModeRestricted, nil); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(readCalls(t, logPath), "add rule ip coi input"); n != 6 {
		t.Errorf("want 6 input rule adds, got %d", n)
	}
}

func TestParseInputRulesForDelete(t *testing.T) {
	listing := `table ip coi {
	chain input { # handle 3
		type filter hook input priority filter; policy accept;
		ip saddr 10.0.0.2 meta l4proto { tcp, udp } th dport 53 reject comment "coi-10.0.0.2" # handle 7
		ip saddr 10.0.0.2 reject comment "coi-10.0.0.2" # handle 8
		ip saddr 10.0.0.20 reject comment "coi-10.0.0.20" # handle 9
	}
}`
	rules := parseChainRules(listing, "coi-10.0.0.2")
	if len(rules) != 2 || rules[0].handle != "7" || rules[1].handle != "8" {
		t.Errorf("got %+v", rules)
	}
}

func TestParseCOIChainRules(t *testing.T) {
	listing := `table ip coi { # handle 4
	set coi_s_10_0_0_2 { # handle 9
		type ipv4_addr
		flags interval
		elements = { 1.1.1.1 }
	}
	chain forward { # handle 1
		type filter hook forward priority 10; policy accept;
		ct state established,related accept comment "coi-base" # handle 2
		ip saddr 10.0.0.2 accept comment "coi-10.0.0.2" # handle 5
		ip saddr 10.0.0.20 accept comment "coi-10.0.0.20" # handle 6
	}
	chain input { # handle 3
		type filter hook input priority filter; policy accept;
		ip saddr 10.0.0.2 ct state established,related accept comment "coi-10.0.0.2" # handle 7
		ip saddr 10.0.0.2 reject comment "coi-10.0.0.2" # handle 8
	}
}`
	rules, chains := parseCOIChainRules(listing, "coi-10.0.0.2")
	if !chains["forward"] || !chains["input"] || len(chains) != 2 {
		t.Errorf("chains = %v", chains)
	}
	if f := rules["forward"]; len(f) != 1 || f[0].handle != "5" {
		t.Errorf("forward = %+v", f)
	}
	if in := rules["input"]; len(in) != 2 || in[0].handle != "7" || in[1].handle != "8" {
		t.Errorf("input = %+v", in)
	}
	got := joinCmds(deleteChainRuleCmds("input", rules["input"]))
	if want := []string{"delete rule ip coi input handle 7", "delete rule ip coi input handle 8"}; !reflect.DeepEqual(got, want) {
		t.Errorf("deletes = %v", got)
	}

	_, chains = parseCOIChainRules("table ip coi {\n\tchain forward {\n\t}\n}", "coi-10.0.0.2")
	if chains["input"] {
		t.Error("a table without an input chain must not report one")
	}
}
