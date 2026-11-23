package network

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// forwardRulesTo returns the forward rules the batch holds for one destination.
func forwardRulesTo(batch [][]string, cidr string) []string {
	var rules []string
	for _, r := range joinCmds(batch) {
		if strings.Contains(r, "ip coi forward") && strings.Contains(r, " ip daddr "+cidr+" ") {
			rules = append(rules, r)
		}
	}
	return rules
}

// The RFC 6598 shared address space (Tailscale, Headscale, NetBird peers) is a
// private range: rejected unless allow_local_network_access opens it, like RFC1918.
func TestPrivateRules_SharedAddressSpace(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name  string
		mode  config.NetworkMode
		local *bool
		ports []int
		want  []string // verdicts of the 100.64.0.0/10 rules, in order
	}{
		{"restricted", config.NetworkModeRestricted, &off, nil, []string{"reject with tcp reset", "reject comment"}},
		{"restricted local access", config.NetworkModeRestricted, &on, nil, []string{"accept"}},
		{"restricted local access ports", config.NetworkModeRestricted, &on, []int{443}, []string{"dport { 443 } accept"}},
		{"allowlist", config.NetworkModeAllowlist, &off, nil, []string{"reject with tcp reset", "reject comment"}},
		{"allowlist local access", config.NetworkModeAllowlist, &on, nil, []string{"accept"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.NetworkConfig{AllowLocalNetworkAccess: tc.local, BlockPrivateNetworks: &on}
			f := NewNftManager("10.0.0.2", "10.0.0.1")
			f.beginBatch(nil)
			var err error
			if tc.mode == config.NetworkModeRestricted {
				err = f.addRestrictedRules(cfg, nil, tc.ports)
			} else {
				err = f.addAllowlistRules(cfg, tc.ports)
			}
			if err != nil {
				t.Fatal(err)
			}
			got := forwardRulesTo(f.batch, "100.64.0.0/10")
			if len(got) != len(tc.want) {
				t.Fatalf("100.64.0.0/10 rules = %q, want verdicts %q", got, tc.want)
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("rule %q, want %q", got[i], w)
				}
			}
			f.abortBatch()
		})
	}
}
