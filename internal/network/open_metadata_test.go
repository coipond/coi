package network

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func TestOpenMetadataCmds(t *testing.T) {
	const ip = "10.0.0.2"
	rules := openModeRuleTexts(ip, true)
	table := func(forward, input, sets string) string {
		return "table ip coi { # handle 1\n" + sets +
			"\tchain forward { # handle 1\n\t\ttype filter hook forward priority filter + 10; policy accept;\n" + forward + "\t}\n" +
			"\tchain input { # handle 2\n\t\ttype filter hook input priority filter; policy accept;\n" + input + "\t}\n}\n"
	}
	base := "\t\tct state established,related accept comment \"coi-base\" # handle 4\n"
	inPlace := base
	for i, r := range rules {
		inPlace += "\t\t" + r + " # handle " + string(rune('5'+i)) + "\n"
	}
	for _, tc := range []struct {
		name    string
		listing string
		inPlace bool
		want    []string // script lines, in order
	}{
		{"no table", "", false, []string{"add table ip coi", "add chain ip coi forward", "coi-base", "169.254.0.0/16 meta l4proto tcp reject", "169.254.0.0/16 reject", "ip saddr 10.0.0.2 accept"}},
		{"in place", table(inPlace, "", ""), true, nil},
		{
			"stale rules and set", table(base+"\t\tip saddr 10.0.0.2 ip daddr @coi_s_10_0_0_2 accept comment \"coi-10.0.0.2\" # handle 9\n",
				"\t\tip saddr 10.0.0.2 udp dport 53 reject comment \"coi-10.0.0.2\" # handle 10\n",
				"\tset coi_s_10_0_0_2 { # handle 3\n\t\ttype ipv4_addr\n\t}\n"), false,
			[]string{"delete rule ip coi forward handle 9", "delete rule ip coi input handle 10", "delete set ip coi coi_s_10_0_0_2", "169.254.0.0/16 meta l4proto tcp reject", "169.254.0.0/16 reject", "accept"},
		},
		{
			"another container's rules stay", table(base+"\t\tip saddr 10.0.0.20 accept comment \"coi-10.0.0.20\" # handle 9\n", "", ""), false,
			[]string{"169.254.0.0/16 meta l4proto tcp reject", "169.254.0.0/16 reject", "accept"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds, inPlace := openMetadataCmds(tc.listing, ip)
			if inPlace != tc.inPlace {
				t.Fatalf("inPlace = %v, want %v", inPlace, tc.inPlace)
			}
			got := joinCmds(cmds)
			if len(got) != len(tc.want) {
				t.Fatalf("script = %q, want %q", got, tc.want)
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("line %d = %q, want %q", i, got[i], w)
				}
			}
		})
	}
}

// Without usable nft the block is not installed, and the caller gets a
// warning to show.
func TestApplyOpenMetadataBlock_NoNft(t *testing.T) {
	off := false
	b, warnings := ApplyOpenMetadataBlock(&config.NetworkConfig{Mode: config.NetworkModeOpen, UseSudo: &off}, "c1")
	if b != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "block_metadata_endpoint is not enforced in open mode") {
		t.Errorf("block = %v, warnings = %q", b, warnings)
	}
	if err := b.Teardown(t.Context(), "c1"); err != nil {
		t.Errorf("nil block teardown: %v", err)
	}
}
