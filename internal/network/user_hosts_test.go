package network

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// TestCheckHostPortsEnforceable pins that a per-host ports scope is refused
// (fail-closed) exactly when the mode/class combination cannot enforce it, and
// allowed when it can — so a user never gets a silently-ignored port cap.
func TestCheckHostPortsEnforceable(t *testing.T) {
	withPorts := func(ip string, ports ...int) config.HostEntry {
		if len(ports) == 0 {
			ports = []int{443}
		}
		return config.HostEntry{IP: ip, Hostnames: []string{"h.local"}, Ports: ports}
	}
	noPorts := func(ip string) config.HostEntry {
		return config.HostEntry{IP: ip, Hostnames: []string{"h.local"}}
	}
	const noLocal, withLocal = false, true
	cases := []struct {
		name         string
		mode         config.NetworkMode
		local        bool
		entry        config.HostEntry
		allowedPorts []int
		wantErr      bool
	}{
		{"no ports is fine for a public host", config.NetworkModeRestricted, noLocal, noPorts("8.8.8.8"), nil, false},
		{"restricted + private enforces", config.NetworkModeRestricted, noLocal, withPorts("192.168.1.50"), nil, false},
		{"restricted + private without ports is fine", config.NetworkModeRestricted, noLocal, noPorts("10.0.0.5"), nil, false},
		{"allowlist + public enforces", config.NetworkModeAllowlist, noLocal, withPorts("1.1.1.1"), nil, false},
		{"restricted + public cannot", config.NetworkModeRestricted, noLocal, withPorts("1.1.1.1"), nil, true},
		{"open mode cannot", config.NetworkModeOpen, noLocal, withPorts("192.168.1.50"), nil, true},

		// allowlist + private, no allow_local_network_access: a targeted accept that
		// must be port-scoped and must not reopen DNS.
		{"allowlist + private with ports enforces", config.NetworkModeAllowlist, noLocal, withPorts("10.50.0.100"), nil, false},
		{"allowlist + private inherits allowed_ports", config.NetworkModeAllowlist, noLocal, noPorts("10.50.0.100"), []int{443}, false},
		{"allowlist + private with no scope at all is refused", config.NetworkModeAllowlist, noLocal, noPorts("10.50.0.100"), nil, true},
		{"allowlist + private on 53 is refused", config.NetworkModeAllowlist, noLocal, withPorts("10.50.0.100", 443, 53), nil, true},
		{"allowlist + private inheriting 53 is refused", config.NetworkModeAllowlist, noLocal, noPorts("10.50.0.100"), []int{53, 443}, true},

		// allowlist + private WITH allow_local_network_access: the LAN accept covers
		// it, so a per-host scope cannot narrow anything.
		{"allowlist + local access + private without ports is fine", config.NetworkModeAllowlist, withLocal, noPorts("192.168.1.50"), nil, false},
		{"allowlist + local access + private with ports cannot", config.NetworkModeAllowlist, withLocal, withPorts("192.168.1.50"), nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkHostPortsEnforceable(c.mode, c.local, c.entry, c.allowedPorts)
			if (err != nil) != c.wantErr {
				t.Fatalf("checkHostPortsEnforceable(%s, local=%v, %s, %v) err = %v, wantErr %v",
					c.mode, c.local, c.entry.IP, c.allowedPorts, err, c.wantErr)
			}
		})
	}
}

// A [[network.hosts]] private-IP entry punches a targeted accept at the head of
// the coi forward chain. Without a port cap that is the historic all-protocol
// hole; with allowed_ports set the accept MUST be scoped to those dports, or a
// host entry silently reopens the full port range (SSH/DB/admin) on a LAN box —
// exactly the lateral-movement the egress cap exists to prevent.
func TestContainerAcceptRuleArgs(t *testing.T) {
	const c, d = "10.1.2.3", "192.168.1.50"
	joined := func(a []string) string { return strings.Join(a, " ") }

	t.Run("no cap keeps the all-protocol accept", func(t *testing.T) {
		got := joined(containerAcceptRuleArgs(c, d, nil))
		want := `insert rule ip coi forward ip saddr 10.1.2.3 ip daddr 192.168.1.50/32 accept comment "coi-10.1.2.3"`
		if got != want {
			t.Fatalf("unscoped rule mismatch:\n got: %s\nwant: %s", got, want)
		}
	})

	t.Run("cap scopes the accept to allowed dports", func(t *testing.T) {
		got := joined(containerAcceptRuleArgs(c, d, []int{80, 443}))
		// The l4 match must sit between the daddr and the accept verb so the host is
		// reachable ONLY on the capped ports.
		want := `insert rule ip coi forward ip saddr 10.1.2.3 ip daddr 192.168.1.50/32 ` +
			`meta l4proto { tcp, udp } th dport { 80, 443 } accept comment "coi-10.1.2.3"`
		if got != want {
			t.Fatalf("scoped rule mismatch:\n got: %s\nwant: %s", got, want)
		}
		if strings.Contains(got, "th dport { 80, 443 } accept") == false {
			t.Errorf("port set must immediately precede accept, got: %s", got)
		}
	})

	t.Run("a capped host is not reachable on an un-listed port", func(t *testing.T) {
		got := joined(containerAcceptRuleArgs(c, d, []int{443}))
		if strings.Contains(got, "22") {
			t.Errorf("cap=[443] must not mention port 22 (SSH): %s", got)
		}
		if !strings.Contains(got, "dport { 443 }") {
			t.Errorf("cap=[443] should render a single-port set: %s", got)
		}
	})
}

func TestClassifyHostIP(t *testing.T) {
	cases := map[string]hostIPClass{
		"1.2.3.4":         hostPublic,
		"8.8.8.8":         hostPublic,
		"10.0.0.5":        hostPrivate,
		"172.16.0.1":      hostPrivate,
		"192.168.1.1":     hostPrivate,
		"169.254.169.254": hostMetadata,
		"169.254.0.1":     hostMetadata,
	}
	for ip, want := range cases {
		if got := classifyHostIP(ip); got != want {
			t.Errorf("classifyHostIP(%s) = %d, want %d", ip, got, want)
		}
	}
}

func TestCheckHostReachable(t *testing.T) {
	// allowlist: public and private reachable (private via a targeted accept or
	// allow_local_network_access — the port scope is checkHostPortsEnforceable's
	// call, see coipond/coi#605); metadata refused.
	for _, ip := range []string{"1.2.3.4", "10.0.0.5", "192.168.1.50"} {
		if err := checkHostReachable(config.NetworkModeAllowlist, ip); err != nil {
			t.Errorf("allowlist %s should be reachable: %v", ip, err)
		}
	}
	if err := checkHostReachable(config.NetworkModeAllowlist, "169.254.169.254"); err == nil {
		t.Error("allowlist metadata must be refused")
	}

	// restricted: public + private reachable (private via targeted allow), metadata refused.
	if err := checkHostReachable(config.NetworkModeRestricted, "10.0.0.5"); err != nil {
		t.Errorf("restricted private should be reachable: %v", err)
	}
	if err := checkHostReachable(config.NetworkModeRestricted, "169.254.169.254"); err == nil {
		t.Error("restricted metadata must be refused")
	}
	// open: anything goes.
	for _, ip := range []string{"10.0.0.5", "169.254.169.254", "1.2.3.4"} {
		if err := checkHostReachable(config.NetworkModeOpen, ip); err != nil {
			t.Errorf("open should allow %s: %v", ip, err)
		}
	}
}

func TestRenderAndParseUserHostsBlock_RoundTrip(t *testing.T) {
	entries := []config.HostEntry{
		{IP: "10.0.0.5", Hostnames: []string{"db.internal", "cache.internal"}},
		{IP: "1.2.3.4", Hostnames: []string{"api.example"}},
	}
	block := renderUserHostsBlock(entries)

	// Parse it back out of a realistic /etc/hosts, with lines around the block.
	hostsFile := "127.0.0.1 localhost\n" + block + "\n1.1.1.1 other\n"
	got := parseUserHostsBlock(hostsFile)
	if len(got) != 2 {
		t.Fatalf("round-trip parsed %d entries, want 2: %+v", len(got), got)
	}
	// render sorts by IP: "1.2.3.4" < "10.0.0.5" (string order)
	if got[0].IP != "1.2.3.4" || got[1].IP != "10.0.0.5" {
		t.Errorf("unexpected IPs/order: %+v", got)
	}
	if len(got[1].Hostnames) != 2 {
		t.Errorf("db entry should keep both hostnames: %+v", got[1])
	}
}

func TestParseUserHostsBlock_NoBlock(t *testing.T) {
	if got := parseUserHostsBlock("127.0.0.1 localhost\n1.1.1.1 x\n"); len(got) != 0 {
		t.Errorf("a file with no coi block must parse to nothing, got %+v", got)
	}
}

func TestMergeHostEntry(t *testing.T) {
	// Same IP → union hostnames (no duplicate).
	base := []config.HostEntry{{IP: "10.0.0.5", Hostnames: []string{"db"}}}
	m := mergeHostEntry(base, config.HostEntry{IP: "10.0.0.5", Hostnames: []string{"db", "cache"}})
	if len(m) != 1 || len(m[0].Hostnames) != 2 {
		t.Errorf("same-IP merge should union hostnames, got %+v", m)
	}

	// New IP → append.
	base2 := []config.HostEntry{{IP: "10.0.0.5", Hostnames: []string{"db"}}}
	m2 := mergeHostEntry(base2, config.HostEntry{IP: "1.2.3.4", Hostnames: []string{"api"}})
	if len(m2) != 2 {
		t.Errorf("new-IP merge should append, got %+v", m2)
	}
}
