package config

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	coischema "github.com/coipond/coi/schema"
)

// PermissionModes and the profile schema's enum are one valid set: a value one
// accepts and the other warns about would confuse.
func TestPermissionModesMatchSchemaEnum(t *testing.T) {
	raw, err := coischema.GetProfileSchema()
	if err != nil {
		t.Fatalf("GetProfileSchema: %v", err)
	}
	var doc struct {
		Defs struct {
			ToolConfig struct {
				Properties struct {
					PermissionMode struct {
						Enum []string `json:"enum"`
					} `json:"permission_mode"`
				} `json:"properties"`
			} `json:"ToolConfig"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	want := []string{""}
	for _, m := range PermissionModes {
		want = append(want, string(m))
	}
	got := doc.Defs.ToolConfig.Properties.PermissionMode.Enum
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("schema permission_mode enum = %q, want %q (PermissionModes plus unset)", got, want)
	}
}

func TestUnknownPermissionModeWarning(t *testing.T) {
	for _, mode := range []PermissionMode{"", PermissionModeBypass, PermissionModeInteractive} {
		if msg := UnknownPermissionModeWarning(mode); msg != "" {
			t.Errorf("%q: unexpected warning %q", mode, msg)
		}
	}
	for _, mode := range []PermissionMode{"Interactive", "ask", " bypass"} {
		msg := UnknownPermissionModeWarning(mode)
		for _, want := range []string{`"` + string(mode) + `"`, `valid: "bypass", "interactive"`, `using "bypass"`} {
			if !strings.Contains(msg, want) {
				t.Errorf("%q: warning %q lacks %s", mode, msg, want)
			}
		}
	}
}
