package network

import (
	"strings"
	"testing"
)

func TestNftScript(t *testing.T) {
	got := nftScript([][]string{
		{"delete", "rule", "ip", "coi", "forward", "handle", "7"},
		{"add", "rule", "ip", "coi", "forward", "ip", "saddr", "10.0.0.2", "accept", "comment", `"coi-10.0.0.2"`},
	})
	want := "delete rule ip coi forward handle 7\nadd rule ip coi forward ip saddr 10.0.0.2 accept comment \"coi-10.0.0.2\"\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestParseForwardRules(t *testing.T) {
	listing := `table ip coi {
	chain forward { # handle 1
		type filter hook forward priority 10; policy accept;
		ct state established,related accept comment "coi-base" # handle 2
		ip saddr 10.0.0.2 accept comment "coi-10.0.0.2" # handle 5
		ip saddr 10.0.0.20 accept comment "coi-10.0.0.20" # handle 6
		iifname "veth1" drop comment "coi-boot-c1" # handle 9
	}
}`
	rules := parseForwardRules(listing, "coi-10.0.0.2")
	if len(rules) != 1 || rules[0].handle != "5" || rules[0].text != openModeRuleText("10.0.0.2") {
		t.Errorf("got %+v", rules)
	}
	if cmds := deleteForwardRuleCmds(rules); len(cmds) != 1 || strings.Join(cmds[0], " ") != "delete rule ip coi forward handle 5" {
		t.Errorf("delete cmds = %v", cmds)
	}
}

// Batching collects rule adds instead of executing them.
func TestNftManagerBatchCollectsRules(t *testing.T) {
	f := NewNftManager("10.0.0.2", "10.0.0.1")
	f.beginBatch([][]string{{"delete", "rule", "ip", "coi", "forward", "handle", "3"}})
	if err := f.addRule("10.0.0.2", "10.0.0.0/8", "reject"); err != nil {
		t.Fatal(err)
	}
	if len(f.batch) != 2 || f.batch[0][0] != "delete" || f.batch[1][0] != "add" {
		t.Errorf("batch = %v", f.batch)
	}
	f.abortBatch()
	if f.batch != nil {
		t.Error("abort must clear the batch")
	}
}

func TestParseInstanceNet(t *testing.T) {
	out := `[{"name":"c1","state":{"network":{"eth0":{"host_name":"veth12","addresses":[{"family":"inet6","address":"fe80::1"},{"family":"inet","address":"10.0.0.2"}]},"lo":{"host_name":""}}}},
	{"name":"c10","state":{"network":{"eth0":{"host_name":"veth99","addresses":[{"family":"inet","address":"10.0.0.9"}]}}}}]`
	ip, veth, err := parseInstanceNet(out, "c1")
	if err != nil || ip != "10.0.0.2" || veth != "veth12" {
		t.Errorf("got %q %q %v", ip, veth, err)
	}
	ip, veth, _ = parseInstanceNet(`[{"name":"c1","state":{"network":{"eth0":{"host_name":"veth12","addresses":[]}}}}]`, "c1")
	if ip != "" || veth != "veth12" {
		t.Errorf("no lease yet: got %q %q", ip, veth)
	}
}
