package network

import (
	"os"
	"path/filepath"
	"reflect"
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
	rules := parseChainRules(listing, "coi-10.0.0.2")
	if len(rules) != 1 || rules[0].handle != "5" || rules[0].text != openModeRuleText("10.0.0.2") {
		t.Errorf("got %+v", rules)
	}
	if cmds := deleteChainRuleCmds("forward", rules); len(cmds) != 1 || strings.Join(cmds[0], " ") != "delete rule ip coi forward handle 5" {
		t.Errorf("delete cmds = %v", cmds)
	}
}

// Batching collects rule adds instead of executing them.
func TestNftManagerBatchCollectsRules(t *testing.T) {
	f := NewNftManager("10.0.0.2", "10.0.0.1")
	f.beginBatch([][]string{{"delete", "rule", "ip", "coi", "forward", "handle", "3"}})
	if err := f.addRule("10.0.0.2", "10.0.0.0/8", "accept"); err != nil {
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

// A reject answers TCP with a reset first, so blocked TCP does not use up the
// container's ICMP rate-limit budget that a blocked DNS query needs.
func TestNftManagerRejectAddsTCPReset(t *testing.T) {
	f := NewNftManager("10.0.0.2", "10.0.0.1")
	f.beginBatch(nil)
	if err := f.addRule("10.0.0.2", "10.0.0.0/8", "reject"); err != nil {
		t.Fatal(err)
	}
	got := joinCmds(f.batch)
	want := []string{
		`add rule ip coi forward ip saddr 10.0.0.2 ip daddr 10.0.0.0/8 meta l4proto tcp reject with tcp reset comment "coi-10.0.0.2"`,
		`add rule ip coi forward ip saddr 10.0.0.2 ip daddr 10.0.0.0/8 reject comment "coi-10.0.0.2"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestParseInstanceNet(t *testing.T) {
	out := `{"name":"c1","status":"Running","state":{"network":{"eth0":{"host_name":"veth12","addresses":[{"family":"inet6","address":"fe80::1"},{"family":"inet","address":"10.0.0.2"}]},"lo":{"host_name":""}}}}`
	n, err := parseInstanceNet(out)
	if err != nil || n.ip != "10.0.0.2" || n.veth != "veth12" {
		t.Errorf("got %q %q %v", n.ip, n.veth, err)
	}
	n, _ = parseInstanceNet(`{"state":{"network":{"eth0":{"host_name":"veth12","addresses":[]}}}}`)
	if n.ip != "" || n.veth != "veth12" {
		t.Errorf("no lease yet: got %q %q", n.ip, n.veth)
	}
	n, err = parseInstanceNet(`{"status":"Stopped","state":{"network":null}}`)
	if err != nil || n.ip != "" || n.veth != "" {
		t.Errorf("stopped: got %q %q %v", n.ip, n.veth, err)
	}
	if _, err := parseInstanceNet("not json"); err == nil {
		t.Error("bad JSON: want error")
	}
}

func TestParseInstanceNet_Network(t *testing.T) {
	for _, c := range []struct{ name, devices, want string }{
		{"profile network", `{"eth0":{"type":"nic","network":"incusbr0"},"root":{"type":"disk","pool":"default"}}`, "incusbr0"},
		{"own network", `{"eth0":{"type":"nic","network":"coinet1"}}`, "coinet1"},
		{"bridged parent", `{"eth0":{"type":"nic","nictype":"bridged","parent":"br1"}}`, "br1"},
		{"no eth0", `{"root":{"type":"disk","pool":"default"}}`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := `{"name":"c1","expanded_devices":` + c.devices + `,"state":{"network":{}}}`
			n, err := parseInstanceNet(out)
			if err != nil || n.network != c.want {
				t.Errorf("got %q, %v; want %q", n.network, err, c.want)
			}
		})
	}
}

// A container Incus does not know has no address yet: empty answer, no error.
func TestLookupInstanceNet_NotFound(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'Error: Instance not found' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	n, err := lookupInstanceNet("coi-gone-1")
	if err != nil || n != (instanceNet{}) {
		t.Errorf("got %+v %v", n, err)
	}
}
