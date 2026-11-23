package network

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseDropChainContainers(t *testing.T) {
	output := `table netdev coi {
	chain coi6-coi-abc12345-1 {
		type filter hook ingress device "veth0" priority -500; policy accept;
		meta protocol ip6 counter packets 0 bytes 0 drop comment "coi6-coi-abc12345-1"
	}
	chain coi-boot-coi-def67890-2 {
		type filter hook ingress device "veth1" priority -500; policy accept;
		meta protocol ip udp dport 67 accept comment "coi-boot-coi-def67890-2"
		meta protocol ip counter packets 3 bytes 180 drop comment "coi-boot-coi-def67890-2"
	}
	chain coi6-coi-def67890-2 {
		type filter hook ingress device "veth1" priority -500; policy accept;
		meta protocol ip6 counter packets 0 bytes 0 drop comment "coi6-coi-def67890-2"
	}
	chain coi-boot-coi-killed-3 {
		type filter hook ingress device "veth2" priority -500; policy accept;
		meta protocol ip counter packets 0 bytes 0 drop comment "coi-boot-coi-killed-3"
	}
}`
	got := parseDropChainContainers(output)
	// deduped, order-preserved; a boot-only chain (killed before its mode's
	// rules) is an orphan too
	want := []string{"coi-abc12345-1", "coi-def67890-2", "coi-killed-3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseDropChainContainers() = %v, want %v", got, want)
	}
}

func TestParseDropChainContainers_None(t *testing.T) {
	// Output with no coi6-/coi-boot- chains yields no names (not nil-vs-empty sensitive).
	if got := parseDropChainContainers("table netdev coi {\n\tchain other {\n\t}\n}"); len(got) != 0 {
		t.Errorf("expected no names, got %v", got)
	}
	if got := parseDropChainContainers(""); len(got) != 0 {
		t.Errorf("expected no names for empty input, got %v", got)
	}
}

func TestVethIngressChainCmds(t *testing.T) {
	tests := []struct {
		name  string
		chain string
		rules [][]string
		want  string
	}{
		{"ipv6 block", "coi6-c1", ipv6BlockRules, `add table netdev coi
add chain netdev coi coi6-c1 { type filter hook ingress device "veth9" priority -500 ; policy accept ; }
add rule netdev coi coi6-c1 meta protocol ip6 counter drop comment "coi6-c1"
`},
		{"boot block", "coi-boot-c1", bootBlockRules, `add table netdev coi
add chain netdev coi coi-boot-c1 { type filter hook ingress device "veth9" priority -500 ; policy accept ; }
add rule netdev coi coi-boot-c1 meta protocol ip ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept comment "coi-boot-c1"
add rule netdev coi coi-boot-c1 meta protocol ip counter drop comment "coi-boot-c1"
add rule netdev coi coi-boot-c1 meta protocol ip6 counter drop comment "coi-boot-c1"
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nftScript(vethIngressChainCmds(tt.chain, "veth9", tt.rules)); got != tt.want {
				t.Errorf("script =\n%s\nwant\n%s", got, tt.want)
			}
			if strings.Contains(nftScript(vethIngressChainCmds(tt.chain, "veth9", tt.rules)), "forward") {
				t.Error("drop chain must not hook forward: iifname there is the bridge, not the veth")
			}
		})
	}
}

func TestIngressChainDevice(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"bound", `table netdev coi {
	chain coi6-c1 {
		type filter hook ingress device "vethNEW" priority -500; policy accept;
		meta protocol ip6 counter packets 0 bytes 0 drop comment "coi6-c1"
	}
}`, "vethNEW"},
		{"no device (veth gone)", `table netdev coi {
	chain coi6-c1 {
		type filter hook ingress priority -500; policy accept;
	}
}`, ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ingressChainDevice(tt.output); got != tt.want {
				t.Errorf("ingressChainDevice() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseLegacyIP6RuleContainers(t *testing.T) {
	output := `table ip6 coi {
	chain forward {
		type filter hook forward priority 10; policy accept;
		iifname "veth0" drop comment "coi6-coi-abc12345-1" # handle 5
		iifname "veth1" drop comment "coi6-coi-def67890-2" # handle 6
		iifname "veth0" drop comment "coi6-coi-abc12345-1" # handle 7
	}
}`
	got := parseLegacyIP6RuleContainers(output)
	want := []string{"coi-abc12345-1", "coi-def67890-2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseLegacyIP6RuleContainers() = %v, want %v", got, want)
	}
}
