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

// block_metadata_endpoint rejects 169.254.0.0/16 in allowlist mode ahead of
// the set accepts, whatever allow_local_network_access says.
func TestAllowlistRules_MetadataBlock(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name     string
		local    *bool
		metadata *bool
		reject   bool
	}{
		{"local access, metadata blocked", &on, &on, true},
		{"local access, metadata not blocked", &on, &off, false},
		{"no local access, metadata blocked", &off, &on, true},
		{"no local access, metadata not blocked", &off, &off, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.NetworkConfig{AllowLocalNetworkAccess: tc.local, BlockMetadataEndpoint: tc.metadata}
			f := NewNftManager("10.0.0.2", "10.0.0.1")
			f.beginBatch(nil)
			defer f.abortBatch()
			if err := f.addAllowlistRules(cfg, nil); err != nil {
				t.Fatal(err)
			}
			got := forwardRulesTo(f.batch, metadataCIDR)
			if !tc.reject {
				if len(got) != 0 {
					t.Fatalf("169.254.0.0/16 rules = %q, want none", got)
				}
				return
			}
			if len(got) != 2 || !strings.Contains(got[0], "reject with tcp reset") || !strings.Contains(got[1], "reject comment") {
				t.Fatalf("169.254.0.0/16 rules = %q, want one reject (tcp reset + other)", got)
			}
			rules := joinCmds(f.batch)
			reject, setAccept := -1, -1
			for i, r := range rules {
				if reject < 0 && strings.Contains(r, " ip daddr "+metadataCIDR+" ") {
					reject = i
				}
				if setAccept < 0 && strings.Contains(r, "@"+staticPortSetName("10.0.0.2")) {
					setAccept = i
				}
			}
			if setAccept < 0 || reject > setAccept {
				t.Errorf("metadata reject at %d, first set accept at %d: reject must come first", reject, setAccept)
			}
		})
	}
}
