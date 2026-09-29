package schema_test

import (
	"testing"

	"github.com/mensfeld/coi/schema"
)

// A [network] block using the egress keys (dns_servers, allowed_ports) must
// validate against the bundled schema — otherwise `coi validate profile` would
// reject a config the runtime fully supports.
func TestValidateProfileMap_AcceptsEgressKeys(t *testing.T) {
	profile := map[string]any{
		"network": map[string]any{
			"mode":          "restricted",
			"dns_servers":   []any{"192.168.1.2", "192.168.1.3"},
			"allowed_ports": []any{53, 80, 443},
		},
	}
	if err := schema.ValidateProfileMap(profile); err != nil {
		t.Fatalf("profile with dns_servers/allowed_ports should validate, got: %v", err)
	}
}

// allowed_ports carries a 1..65535 bound in the schema, so an out-of-range port
// must be rejected at validation time (below the range).
func TestValidateProfileMap_RejectsPortZero(t *testing.T) {
	profile := map[string]any{
		"network": map[string]any{"allowed_ports": []any{0}},
	}
	if err := schema.ValidateProfileMap(profile); err == nil {
		t.Fatal("allowed_ports=[0] should be rejected (below minimum 1)")
	}
}

// ...and above the range.
func TestValidateProfileMap_RejectsPortTooLarge(t *testing.T) {
	profile := map[string]any{
		"network": map[string]any{"allowed_ports": []any{70000}},
	}
	if err := schema.ValidateProfileMap(profile); err == nil {
		t.Fatal("allowed_ports=[70000] should be rejected (above maximum 65535)")
	}
}

// allowed_ports is an integer array; a string element must be rejected.
func TestValidateProfileMap_RejectsNonIntegerPort(t *testing.T) {
	profile := map[string]any{
		"network": map[string]any{"allowed_ports": []any{"443"}},
	}
	if err := schema.ValidateProfileMap(profile); err == nil {
		t.Fatal("allowed_ports with a string element should be rejected")
	}
}

// dns_servers is a string array; a non-string element must be rejected.
func TestValidateProfileMap_RejectsNonStringDNSServer(t *testing.T) {
	profile := map[string]any{
		"network": map[string]any{"dns_servers": []any{53}},
	}
	if err := schema.ValidateProfileMap(profile); err == nil {
		t.Fatal("dns_servers with a non-string element should be rejected")
	}
}

// additionalProperties:false on NetworkConfig must still reject unknown keys —
// a guard that adding the two new keys did not accidentally loosen the schema.
func TestValidateProfileMap_RejectsUnknownNetworkKey(t *testing.T) {
	profile := map[string]any{
		"network": map[string]any{"dns_serverz": []any{"192.168.1.2"}},
	}
	if err := schema.ValidateProfileMap(profile); err == nil {
		t.Fatal("unknown network key should be rejected by additionalProperties:false")
	}
}

// The boundary values 1 and 65535 must be accepted (inclusive bounds).
func TestValidateProfileMap_AcceptsPortBoundaries(t *testing.T) {
	profile := map[string]any{
		"network": map[string]any{"allowed_ports": []any{1, 65535}},
	}
	if err := schema.ValidateProfileMap(profile); err != nil {
		t.Fatalf("boundary ports 1 and 65535 should validate, got: %v", err)
	}
}
