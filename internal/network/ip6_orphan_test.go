package network

import (
	"reflect"
	"testing"
)

func TestParseCOIIP6RuleContainers(t *testing.T) {
	output := `table ip6 coi {
	chain forward {
		type filter hook forward priority 10; policy accept;
		ct state established,related accept comment "coi-base" # handle 4
		iifname "veth0" drop comment "coi6-coi-abc12345-1" # handle 5
		iifname "veth1" drop comment "coi6-coi-def67890-2" # handle 6
		iifname "veth0" drop comment "coi6-coi-abc12345-1" # handle 7
	}
}`
	got := parseCOIIP6RuleContainers(output)
	want := []string{"coi-abc12345-1", "coi-def67890-2"} // deduped, order-preserved
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCOIIP6RuleContainers() = %v, want %v", got, want)
	}
}

func TestParseCOIIP6RuleContainers_None(t *testing.T) {
	// Output with no coi6- comments yields no names (not nil-vs-empty sensitive).
	if got := parseCOIIP6RuleContainers("chain forward { ct state established accept }"); len(got) != 0 {
		t.Errorf("expected no names, got %v", got)
	}
	if got := parseCOIIP6RuleContainers(""); len(got) != 0 {
		t.Errorf("expected no names for empty input, got %v", got)
	}
}

func TestVethRulePlan(t *testing.T) {
	chain := `table ip6 coi {
	chain forward {
		type filter hook forward priority 10; policy accept;
		iifname "vethOLD" drop comment "coi6-coi-abc12345-1" # handle 5
		iifname "vethNEW" drop comment "coi6-coi-abc12345-1" # handle 6
		iifname "vethNEW" drop comment "coi6-coi-abc12345-1" # handle 7
		iifname "vethX" drop comment "coi6-coi-abc12345-10" # handle 8
		iifname "vethNEWER" drop comment "coi6-coi-def67890-2" # handle 9
	}
}`
	const comment = "coi6-coi-abc12345-1"
	tests := []struct {
		name        string
		output      string
		veth        string
		wantCurrent bool
		wantStale   []string
	}{
		{"no rule yet", "", "vethNEW", false, nil},
		// The bug: a rule left over from an earlier start names a dead veth.
		{"only a stale rule", `iifname "vethOLD" drop comment "coi6-coi-abc12345-1" # handle 5`, "vethNEW", false, []string{"5"}},
		{"already current", `iifname "vethNEW" drop comment "coi6-coi-abc12345-1" # handle 6`, "vethNEW", true, nil},
		// Keeps one current rule, drops the stale one and the duplicate; never
		// touches another container's rule (coi6-...-10 must not match ...-1).
		{"stale plus duplicates", chain, "vethNEW", true, []string{"5", "7"}},
		// A veth name that is a prefix of another must not count as current.
		{"prefix veth", chain, "vethNE", false, []string{"5", "6", "7"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current, stale := vethRulePlan(tt.output, comment, tt.veth)
			if current != tt.wantCurrent || !reflect.DeepEqual(stale, tt.wantStale) {
				t.Errorf("vethRulePlan() = (%v, %v), want (%v, %v)", current, stale, tt.wantCurrent, tt.wantStale)
			}
		})
	}
}
