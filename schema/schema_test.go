package schema_test

import (
	"encoding/json"
	"testing"

	"github.com/coipond/coi/schema"
)

func mustGetSchema(t *testing.T) []byte {
	t.Helper()
	b, err := schema.GetProfileSchema()
	if err != nil {
		t.Fatalf("GetProfileSchema returned error: %v", err)
	}
	return b
}

func TestGetProfileSchema_NonEmpty(t *testing.T) {
	b := mustGetSchema(t)
	if len(b) == 0 {
		t.Fatal("GetProfileSchema returned empty bytes")
	}
}

func TestGetProfileSchema_ValidJSON(t *testing.T) {
	b := mustGetSchema(t)
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("bundled profile schema is not valid JSON: %v", err)
	}
}

func TestGetProfileSchema_RequiredMetaFields(t *testing.T) {
	b := mustGetSchema(t)
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	for _, key := range []string{"$schema", "$id", "title", "type", "properties", "$defs"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("bundled schema is missing top-level key %q", key)
		}
	}
}

func TestGetProfileSchema_AllDefsPresent(t *testing.T) {
	b := mustGetSchema(t)
	var doc struct {
		Defs map[string]any `json:"$defs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	expected := []string{
		"BuildConfig", "ContainerConfig",
		"CPULimits", "MemoryLimits", "DiskLimits", "RuntimeLimits", "LimitsConfig",
		"ClaudeToolConfig", "CodexToolConfig", "ToolConfig",
		"MountEntry", "SocketEntry", "CredentialEntry",
		"NetworkLoggingConfig", "NetworkConfig",
		"PathsConfig", "IncusConfig",
		"GitConfig", "SSHConfig",
		"SecurityConfig",
		"NFTMonitoringConfig", "MonitoringConfig",
		"TimezoneConfig", "ShellConfig",
	}
	for _, name := range expected {
		if _, ok := doc.Defs[name]; !ok {
			t.Errorf("bundled schema is missing $defs[%q]", name)
		}
	}
}

func TestGetProfileSchema_NetworkModeEnum(t *testing.T) {
	b := mustGetSchema(t)
	var doc struct {
		Defs struct {
			NetworkConfig struct {
				Properties struct {
					Mode struct {
						Enum []any `json:"enum"`
					} `json:"mode"`
				} `json:"properties"`
			} `json:"NetworkConfig"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}

	modes := doc.Defs.NetworkConfig.Properties.Mode.Enum
	if len(modes) == 0 {
		t.Fatal("network mode enum is empty in bundled schema")
	}
	want := map[string]bool{"open": false, "restricted": false, "allowlist": false}
	for _, v := range modes {
		if s, ok := v.(string); ok {
			want[s] = true
		}
	}
	for mode, found := range want {
		if !found {
			t.Errorf("network mode enum missing %q in bundled schema", mode)
		}
	}
}

func TestGetProfileSchema_MountEntryRequiresHostAndContainer(t *testing.T) {
	b := mustGetSchema(t)
	var doc struct {
		Defs struct {
			MountEntry struct {
				Required []string `json:"required"`
			} `json:"MountEntry"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	required := make(map[string]bool)
	for _, f := range doc.Defs.MountEntry.Required {
		required[f] = true
	}
	for _, field := range []string{"host", "container"} {
		if !required[field] {
			t.Errorf("MountEntry.required is missing %q in bundled schema", field)
		}
	}
}

func TestGetProfileSchema_SocketEntryRequiresHostAndContainer(t *testing.T) {
	b := mustGetSchema(t)
	var doc struct {
		Defs struct {
			SocketEntry struct {
				Required             []string `json:"required"`
				AdditionalProperties bool     `json:"additionalProperties"`
				Properties           struct {
					Env map[string]any `json:"env"`
				} `json:"properties"`
			} `json:"SocketEntry"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	required := make(map[string]bool)
	for _, f := range doc.Defs.SocketEntry.Required {
		required[f] = true
	}
	for _, field := range []string{"host", "container"} {
		if !required[field] {
			t.Errorf("SocketEntry.required is missing %q in bundled schema", field)
		}
	}
	if doc.Defs.SocketEntry.AdditionalProperties {
		t.Error("SocketEntry should set additionalProperties:false to reject unknown keys")
	}
	if doc.Defs.SocketEntry.Properties.Env == nil {
		t.Error("SocketEntry should declare an optional 'env' property")
	}
}

// The profile schema must wire a top-level `sockets` array referencing SocketEntry.
func TestGetProfileSchema_SocketsArrayWired(t *testing.T) {
	b := mustGetSchema(t)
	var doc struct {
		Properties struct {
			Sockets struct {
				Type  string `json:"type"`
				Items struct {
					Ref string `json:"$ref"`
				} `json:"items"`
			} `json:"sockets"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	if doc.Properties.Sockets.Type != "array" {
		t.Errorf("profile schema 'sockets' should be an array, got %q", doc.Properties.Sockets.Type)
	}
	if doc.Properties.Sockets.Items.Ref != "#/$defs/SocketEntry" {
		t.Errorf("profile schema 'sockets' items should $ref SocketEntry, got %q", doc.Properties.Sockets.Items.Ref)
	}
}

// The profile schema must wire a top-level `ports` object whose `map` array
// references PortEntry (drift guard, like the sockets sibling above).
func TestGetProfileSchema_PortsWired(t *testing.T) {
	b := mustGetSchema(t)
	var doc struct {
		Properties struct {
			Ports struct {
				Type       string `json:"type"`
				Properties struct {
					Pool struct {
						Type    string `json:"type"`
						Maximum int    `json:"maximum"`
					} `json:"pool"`
					Map struct {
						Type  string `json:"type"`
						Items struct {
							Ref string `json:"$ref"`
						} `json:"items"`
					} `json:"map"`
				} `json:"properties"`
			} `json:"ports"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	if doc.Properties.Ports.Type != "object" {
		t.Errorf("profile schema 'ports' should be an object, got %q", doc.Properties.Ports.Type)
	}
	if doc.Properties.Ports.Properties.Pool.Type != "integer" || doc.Properties.Ports.Properties.Pool.Maximum != 10 {
		t.Errorf("profile schema 'ports.pool' should be an integer capped at 10, got %+v", doc.Properties.Ports.Properties.Pool)
	}
	if doc.Properties.Ports.Properties.Map.Items.Ref != "#/$defs/PortEntry" {
		t.Errorf("profile schema 'ports.map' items should $ref PortEntry, got %q", doc.Properties.Ports.Properties.Map.Items.Ref)
	}
}

// The profile schema must expose an `env_commands` object of string values.
func TestGetProfileSchema_EnvCommandsWired(t *testing.T) {
	b := mustGetSchema(t)
	var doc struct {
		Properties struct {
			EnvCommands struct {
				Type                 string         `json:"type"`
				AdditionalProperties map[string]any `json:"additionalProperties"`
			} `json:"env_commands"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	if doc.Properties.EnvCommands.Type != "object" {
		t.Errorf("profile schema 'env_commands' should be an object, got %q", doc.Properties.EnvCommands.Type)
	}
	if doc.Properties.EnvCommands.AdditionalProperties["type"] != "string" {
		t.Errorf("env_commands values should be strings, got %v", doc.Properties.EnvCommands.AdditionalProperties)
	}
}

// Regression: these keys are supported by the Go structs but were missing from
// the JSON schema, so `coi validate profile` rejected valid profiles that used
// them (container.stale_base_check, monitoring.process_count_threshold,
// monitoring.process_spawn_rate_threshold). ValidateProfileMap must now accept them.
func TestValidateProfileMap_AcceptsStructSupportedKeys(t *testing.T) {
	profile := map[string]any{
		"container": map[string]any{
			"stale_base_check": "error",
		},
		"monitoring": map[string]any{
			"process_count_threshold":      256,
			"process_spawn_rate_threshold": 100,
		},
	}
	if err := schema.ValidateProfileMap(profile); err != nil {
		t.Fatalf("profile with struct-supported keys should validate, got: %v", err)
	}
}

// container.build.agents (#454) must validate as a string array.
func TestValidateProfileMap_AcceptsBuildAgents(t *testing.T) {
	profile := map[string]any{
		"container": map[string]any{
			"build": map[string]any{"agents": []any{"claude", "opencode"}},
		},
	}
	if err := schema.ValidateProfileMap(profile); err != nil {
		t.Fatalf("profile with [container.build] agents should validate, got: %v", err)
	}
}

// stale_base_check is constrained to the enum the runtime understands.
func TestValidateProfileMap_RejectsBadStaleBaseCheck(t *testing.T) {
	profile := map[string]any{
		"container": map[string]any{"stale_base_check": "loud"},
	}
	if err := schema.ValidateProfileMap(profile); err == nil {
		t.Fatal("stale_base_check='loud' should be rejected (not in enum)")
	}
}

// A per-mount `shift` boolean (#604) must validate in both mount shapes and
// must be rejected when it is not a boolean.
func TestValidateProfileMap_MountShift(t *testing.T) {
	valid := map[string]any{
		"mounts": []any{
			map[string]any{"host": "/h", "container": "/c", "shift": true},
		},
	}
	if err := schema.ValidateProfileMap(valid); err != nil {
		t.Fatalf("mount with shift=true should validate, got: %v", err)
	}

	nested := map[string]any{
		"mounts": map[string]any{
			"default": []any{
				map[string]any{"host": "/h", "container": "/c", "shift": false},
			},
		},
	}
	if err := schema.ValidateProfileMap(nested); err != nil {
		t.Fatalf("nested mount with shift=false should validate, got: %v", err)
	}

	bad := map[string]any{
		"mounts": []any{
			map[string]any{"host": "/h", "container": "/c", "shift": "yes"},
		},
	}
	if err := schema.ValidateProfileMap(bad); err == nil {
		t.Fatal("mount shift must be a boolean; string should be rejected")
	}
}

// The strict schema must still reject genuinely unknown keys.
func TestValidateProfileMap_RejectsUnknownKey(t *testing.T) {
	profile := map[string]any{
		"container": map[string]any{"bogus_key": true},
	}
	if err := schema.ValidateProfileMap(profile); err == nil {
		t.Fatal("unknown container key should be rejected by additionalProperties:false")
	}
}

// A profile with a [prompts] table (both inline-string and { file = "..." }
// forms) must validate, and a malformed entry must be rejected (#701).
func TestValidateProfileMap_Prompts(t *testing.T) {
	valid := map[string]any{
		"prompts": map[string]any{
			"inline": "say hello",
			"fromfile": map[string]any{
				"file": "prompts/triage.md",
			},
		},
	}
	if err := schema.ValidateProfileMap(valid); err != nil {
		t.Fatalf("valid [prompts] should pass, got %v", err)
	}

	badShape := map[string]any{
		"prompts": map[string]any{
			"x": 123, // neither string nor { file }
		},
	}
	if err := schema.ValidateProfileMap(badShape); err == nil {
		t.Fatal("a non-string, non-file prompt entry should be rejected")
	}

	badKey := map[string]any{
		"prompts": map[string]any{
			"x": map[string]any{"path": "nope"}, // wrong key
		},
	}
	if err := schema.ValidateProfileMap(badKey); err == nil {
		t.Fatal("a prompt table with the wrong key should be rejected")
	}
}

func TestGetProfileSchema_Deterministic(t *testing.T) {
	a, err := schema.GetProfileSchema()
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	b, err := schema.GetProfileSchema()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("GetProfileSchema is not deterministic across calls")
	}
}

// [tool] binary takes a command name or path, never a shell snippet (it is
// launched inside a shell command string); the schema mirrors
// tool.ValidateBinary.
func TestValidateProfileMap_ToolBinary(t *testing.T) {
	for _, ok := range []string{"claude", "/workspace/claude-wrapper.sh", "./bin/agent"} {
		if err := schema.ValidateProfileMap(map[string]any{"tool": map[string]any{"binary": ok}}); err != nil {
			t.Errorf("binary %q should validate, got: %v", ok, err)
		}
	}
	for _, bad := range []string{"claude update; claude", "/path with space/claude", "-x"} {
		if err := schema.ValidateProfileMap(map[string]any{"tool": map[string]any{"binary": bad}}); err == nil {
			t.Errorf("binary %q should be rejected", bad)
		}
	}
}

// [tool] pre_launch is a list of non-empty command strings.
func TestValidateProfileMap_ToolPreLaunch(t *testing.T) {
	if err := schema.ValidateProfileMap(map[string]any{"tool": map[string]any{"pre_launch": []any{"claude update", "echo ok && true"}}}); err != nil {
		t.Errorf("pre_launch list should validate, got: %v", err)
	}
	for _, bad := range []any{"claude update", []any{""}, []any{42}} {
		if err := schema.ValidateProfileMap(map[string]any{"tool": map[string]any{"pre_launch": bad}}); err == nil {
			t.Errorf("pre_launch %v should be rejected", bad)
		}
	}
}
