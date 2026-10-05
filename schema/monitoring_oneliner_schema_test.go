package schema_test

import (
	"testing"

	"github.com/coipond/coi/schema"
)

// The #842 [monitoring] reverse_shell_one_liners knob is an enum:
// "critical" | "warn" | "off". Valid values must validate.
func TestValidateProfileMap_AcceptsReverseShellOneLiners(t *testing.T) {
	for _, v := range []string{"critical", "warn", "off"} {
		profile := map[string]any{
			"monitoring": map[string]any{"reverse_shell_one_liners": v},
		}
		if err := schema.ValidateProfileMap(profile); err != nil {
			t.Fatalf("reverse_shell_one_liners=%q should validate, got: %v", v, err)
		}
	}
}

// An out-of-enum value must be rejected with a precise error path so
// `coi validate profile` catches the typo instead of the runtime silently
// falling back to the default.
func TestValidateProfileMap_RejectsBadReverseShellOneLiners(t *testing.T) {
	profile := map[string]any{
		"monitoring": map[string]any{"reverse_shell_one_liners": "warning"},
	}
	if err := schema.ValidateProfileMap(profile); err == nil {
		t.Fatal("reverse_shell_one_liners=\"warning\" should be rejected (not in enum)")
	}
}
