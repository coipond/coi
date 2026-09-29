package session

import (
	"encoding/json"
	"testing"

	"github.com/mensfeld/coi/internal/tool"
)

// TestClaudeSandboxSettings_SkipPermissionPrompt verifies that ClaudeTool's
// sandbox settings include a top-level skipDangerousModePermissionPrompt: true,
// both in the raw settings and after mergeJSONSettings. Claude Code only reads
// this key at the top level of settings.json, not nested under "permissions"
// (mensfeld/coi#649).
func TestClaudeSandboxSettings_SkipPermissionPrompt(t *testing.T) {
	ct := tool.NewClaude()
	settings := ct.GetSandboxSettings()

	// Verify skipDangerousModePermissionPrompt is top-level
	skip, ok := settings["skipDangerousModePermissionPrompt"]
	if !ok {
		t.Fatal("settings missing top-level 'skipDangerousModePermissionPrompt' key")
	}
	if skip != true {
		t.Errorf("skipDangerousModePermissionPrompt = %v, want true", skip)
	}

	// Verify permissions map exists, still carries defaultMode, but no longer
	// carries skipDangerousModePermissionPrompt
	permsRaw, ok := settings["permissions"]
	if !ok {
		t.Fatal("settings missing 'permissions' key")
	}
	perms, ok := permsRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("permissions is %T, want map[string]interface{}", permsRaw)
	}
	if perms["defaultMode"] != "bypassPermissions" {
		t.Errorf("defaultMode = %v, want 'bypassPermissions'", perms["defaultMode"])
	}
	if _, ok := perms["skipDangerousModePermissionPrompt"]; ok {
		t.Error("permissions map should not contain 'skipDangerousModePermissionPrompt'")
	}

	// Verify mergeJSONSettings produces correct JSON with the boolean value
	result, _, err := mergeJSONSettings(nil, settings)
	if err != nil {
		t.Fatalf("mergeJSONSettings() error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Failed to parse merged JSON: %v", err)
	}

	if parsed["skipDangerousModePermissionPrompt"] != true {
		t.Errorf("merged JSON top-level skipDangerousModePermissionPrompt = %v, want true", parsed["skipDangerousModePermissionPrompt"])
	}

	permsParsed, ok := parsed["permissions"].(map[string]interface{})
	if !ok {
		t.Fatalf("merged JSON 'permissions' is %T, want map", parsed["permissions"])
	}
	if permsParsed["defaultMode"] != "bypassPermissions" {
		t.Errorf("merged JSON defaultMode = %v, want 'bypassPermissions'", permsParsed["defaultMode"])
	}
}

// TestClaudeSandboxSettings_InteractiveMode verifies that interactive mode
// does NOT inject bypass permissions or skipDangerousModePermissionPrompt.
func TestClaudeSandboxSettings_InteractiveMode(t *testing.T) {
	ct := &tool.ClaudeTool{}
	ct.SetPermissionMode("interactive")
	settings := ct.GetSandboxSettings()

	if _, ok := settings["permissions"]; ok {
		t.Error("interactive mode should not include 'permissions' key")
	}
	if _, ok := settings["allowDangerouslySkipPermissions"]; ok {
		t.Error("interactive mode should not include 'allowDangerouslySkipPermissions'")
	}
}
