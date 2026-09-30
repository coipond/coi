package network

import (
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func TestValidateDNSServers(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"empty", nil, []string{}, false},
		{"single", []string{"192.168.1.2"}, []string{"192.168.1.2"}, false},
		{"trims and dedups", []string{" 8.8.8.8 ", "8.8.8.8"}, []string{"8.8.8.8"}, false},
		{"multiple order preserved", []string{"192.168.1.2", "1.1.1.1"}, []string{"192.168.1.2", "1.1.1.1"}, false},
		{"rejects hostname", []string{"pihole.local"}, nil, true},
		{"rejects ipv6", []string{"2001:4860:4860::8888"}, nil, true},
		{"rejects garbage", []string{"not-an-ip"}, nil, true},
		{"rejects cidr", []string{"192.168.1.0/24"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateDNSServers(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateAllowedPorts(t *testing.T) {
	tests := []struct {
		name    string
		in      []int
		want    []int
		wantErr bool
	}{
		{"empty", nil, []int{}, false},
		{"sorts and dedups", []int{443, 80, 443}, []int{80, 443}, false},
		{"boundaries ok", []int{1, 65535}, []int{1, 65535}, false},
		{"rejects zero", []int{0}, nil, true},
		{"rejects negative", []int{-1}, nil, true},
		{"rejects too large", []int{65536}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAllowedPorts(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPortSetTokens(t *testing.T) {
	tests := []struct {
		in   []int
		want []string
	}{
		{[]int{443}, []string{"{", "443", "}"}},
		{[]int{80, 443}, []string{"{", "80,", "443", "}"}},
		{[]int{53, 80, 443}, []string{"{", "53,", "80,", "443", "}"}},
	}
	for _, tt := range tests {
		if got := portSetTokens(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("portSetTokens(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// TestL4PortMatchNoPortsIsHistoric pins that with no ports the emitted match is
// byte-identical to the original hard-coded clause, so existing allowlist/restricted
// configs produce exactly the same nft rules as before this change.
func TestL4PortMatchNoPortsIsHistoric(t *testing.T) {
	got := l4PortMatch(nil)
	want := []string{"meta", "l4proto", "{", "tcp,", "udp", "}"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("l4PortMatch(nil) = %v, want historic %v", got, want)
	}
}

func TestL4PortMatchWithPorts(t *testing.T) {
	got := l4PortMatch([]int{80, 443})
	want := []string{"meta", "l4proto", "{", "tcp,", "udp", "}", "th", "dport", "{", "80,", "443", "}"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("l4PortMatch = %v, want %v", got, want)
	}
	// The port constraint must sit AFTER the l4proto clause, or nft rejects the rule.
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "l4proto { tcp, udp } th dport") {
		t.Errorf("port match not ordered after l4proto clause: %q", joined)
	}
}

// TestL4PortMatchEmptySliceIsHistoric ensures an empty (non-nil) slice behaves
// exactly like nil — both must reproduce the historic clause. A caller that
// passes validateAllowedPorts(nil) gets []int{} back, so this guards that path.
func TestL4PortMatchEmptySliceIsHistoric(t *testing.T) {
	historic := []string{"meta", "l4proto", "{", "tcp,", "udp", "}"}
	if got := l4PortMatch([]int{}); !reflect.DeepEqual(got, historic) {
		t.Errorf("l4PortMatch([]int{}) = %v, want %v", got, historic)
	}
	// nil and empty must agree.
	if !reflect.DeepEqual(l4PortMatch(nil), l4PortMatch([]int{})) {
		t.Error("l4PortMatch(nil) and l4PortMatch([]int{}) disagree")
	}
}

// TestValidateAllowedPortsPreservesInputSliceUnmutated guards that validation
// does not sort the caller's slice in place — the config value must be untouched.
func TestValidateAllowedPortsPreservesInputSliceUnmutated(t *testing.T) {
	in := []int{443, 80, 22}
	orig := append([]int(nil), in...)
	if _, err := validateAllowedPorts(in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(in, orig) {
		t.Errorf("validateAllowedPorts mutated its input: got %v, want %v", in, orig)
	}
}

// TestValidateDNSServersPreservesInputSliceUnmutated guards the same for dns.
func TestValidateDNSServersPreservesInputSliceUnmutated(t *testing.T) {
	in := []string{" 8.8.8.8 ", "1.1.1.1"}
	orig := append([]string(nil), in...)
	if _, err := validateDNSServers(in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(in, orig) {
		t.Errorf("validateDNSServers mutated its input: got %v, want %v", in, orig)
	}
}

// TestValidateAllowedPortsErrorMessages checks the operator-facing error text is
// specific enough to fix the config from the message alone.
func TestValidateAllowedPortsErrorMessages(t *testing.T) {
	_, err := validateAllowedPorts([]int{80, 70000})
	if err == nil {
		t.Fatal("expected an error for out-of-range port")
	}
	if !strings.Contains(err.Error(), "70000") || !strings.Contains(err.Error(), "allowed_ports") {
		t.Errorf("error should name the field and the bad value: %v", err)
	}
}

func TestValidateDNSServersErrorMessages(t *testing.T) {
	_, err := validateDNSServers([]string{"1.1.1.1", "nope"})
	if err == nil {
		t.Fatal("expected an error for non-IPv4 entry")
	}
	if !strings.Contains(err.Error(), "nope") || !strings.Contains(err.Error(), "dns_servers") {
		t.Errorf("error should name the field and the bad value: %v", err)
	}
}

// TestValidateAllowedPortsLargeDedup exercises a big, messy input to make sure
// dedup+sort scales and is fully deterministic.
func TestValidateAllowedPortsLargeDedup(t *testing.T) {
	in := []int{443, 80, 443, 8080, 80, 22, 443, 8080, 1, 65535}
	got, err := validateAllowedPorts(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{1, 22, 80, 443, 8080, 65535}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPortSetTokensRoundTripsThroughNftSyntax is a light structural check that the
// tokens join into the literal nft set syntax the kernel expects.
func TestPortSetTokensRoundTripsThroughNftSyntax(t *testing.T) {
	cases := map[string][]int{
		"{ 443 }":         {443},
		"{ 80, 443 }":     {80, 443},
		"{ 53, 80, 443 }": {53, 80, 443},
	}
	for want, ports := range cases {
		if got := strings.Join(portSetTokens(ports), " "); got != want {
			t.Errorf("portSetTokens(%v) joined = %q, want %q", ports, got, want)
		}
	}
}

// The following tests exercise the FAIL-CLOSED validation at the top of
// ApplyRestricted/ApplyAllowlist. Validation runs before any nft/sudo call, so a
// bad value returns an error here with no side effects — and no Incus needed.

func TestApplyRestricted_RejectsBadDNSServers(t *testing.T) {
	f := NewNftManager("10.1.1.1", "10.1.1.254")
	cfg := &config.NetworkConfig{
		Mode:       config.NetworkModeRestricted,
		DNSServers: []string{"not-an-ip"},
	}
	err := f.ApplyRestricted(cfg)
	if err == nil {
		t.Fatal("expected ApplyRestricted to fail closed on an invalid dns_servers entry")
	}
	if !strings.Contains(err.Error(), "dns_servers") {
		t.Errorf("error should name dns_servers, got: %v", err)
	}
}

func TestApplyRestricted_RejectsBadAllowedPorts(t *testing.T) {
	f := NewNftManager("10.1.1.1", "10.1.1.254")
	cfg := &config.NetworkConfig{
		Mode:         config.NetworkModeRestricted,
		AllowedPorts: []int{0},
	}
	err := f.ApplyRestricted(cfg)
	if err == nil {
		t.Fatal("expected ApplyRestricted to fail closed on an out-of-range allowed_ports value")
	}
	if !strings.Contains(err.Error(), "allowed_ports") {
		t.Errorf("error should name allowed_ports, got: %v", err)
	}
}

func TestApplyAllowlist_RejectsBadAllowedPorts(t *testing.T) {
	// Gateway is set so the earlier gateway guard passes and validation is reached.
	f := NewNftManager("10.1.1.1", "10.1.1.254")
	cfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{"1.1.1.1/32"},
		AllowedPorts:   []int{70000},
	}
	err := f.ApplyAllowlist(cfg, []string{"1.1.1.1/32"})
	if err == nil {
		t.Fatal("expected ApplyAllowlist to fail closed on an out-of-range allowed_ports value")
	}
	if !strings.Contains(err.Error(), "allowed_ports") {
		t.Errorf("error should name allowed_ports, got: %v", err)
	}
}

// ApplyAllowlist must still fail closed when the gateway is missing, before it
// ever looks at allowed_ports — the DHCP-renewal invariant takes precedence.
func TestApplyAllowlist_RequiresGatewayBeforePorts(t *testing.T) {
	f := NewNftManager("10.1.1.1", "") // no gateway
	cfg := &config.NetworkConfig{
		Mode:         config.NetworkModeAllowlist,
		AllowedPorts: []int{70000}, // also invalid, but the gateway check must win
	}
	err := f.ApplyAllowlist(cfg, nil)
	if err == nil {
		t.Fatal("expected ApplyAllowlist to fail without a gateway IP")
	}
	if !strings.Contains(err.Error(), "gateway") {
		t.Errorf("error should name the gateway requirement, got: %v", err)
	}
}
