package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/coipond/coi/schema"
)

func TestToolMemory_ParsesFromTOML(t *testing.T) {
	var c Config
	if _, err := toml.Decode("[tool]\nmemory = \"fresh\"\n", &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Tool.Memory != ToolMemoryFresh {
		t.Errorf("Tool.Memory = %q, want %q", c.Tool.Memory, ToolMemoryFresh)
	}
}

// Unset means keep, so nothing changes for existing configs; a later scope
// overrides, an empty one leaves it.
func TestToolMemory_MergeOverrides(t *testing.T) {
	base := &Config{}
	if base.Tool.Memory == ToolMemoryFresh {
		t.Fatal("default must not be fresh")
	}
	base.Merge(&Config{Tool: ToolConfig{Memory: ToolMemoryFresh}})
	if base.Tool.Memory != ToolMemoryFresh {
		t.Errorf("after merge: Memory = %q, want %q", base.Tool.Memory, ToolMemoryFresh)
	}
	base.Merge(&Config{})
	if base.Tool.Memory != ToolMemoryFresh {
		t.Errorf("after empty merge: Memory = %q, want it unchanged", base.Tool.Memory)
	}
	base.Merge(&Config{Tool: ToolConfig{Memory: ToolMemoryKeep}})
	if base.Tool.Memory != ToolMemoryKeep {
		t.Errorf("after keep merge: Memory = %q, want %q", base.Tool.Memory, ToolMemoryKeep)
	}
}

func TestToolMemory_Validation(t *testing.T) {
	for _, ok := range []ToolMemory{"", ToolMemoryKeep, ToolMemoryFresh} {
		if err := validateToolMemory(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []ToolMemory{"Fresh", "none", " keep"} {
		if err := validateToolMemory(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestToolMemory_ProfileSchema(t *testing.T) {
	if err := schema.ValidateProfileMap(map[string]any{"tool": map[string]any{"memory": "fresh"}}); err != nil {
		t.Errorf("memory = fresh should pass the profile schema: %v", err)
	}
	if err := schema.ValidateProfileMap(map[string]any{"tool": map[string]any{"memory": "forget"}}); err == nil {
		t.Error("memory = forget should fail the profile schema")
	}
}

func TestToolMemory_LoadRejectsInvalidValue(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[tool]\nmemory = \"Fresh\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COI_CONFIG", path)
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), `invalid [tool] memory "Fresh"`) {
		t.Fatalf("want an invalid [tool] memory error, got %v", err)
	}
}

// A project config may set it: fresh only narrows what a reused container
// keeps of the tool's memory.
func TestToolMemory_HonoredFromProjectConfig(t *testing.T) {
	cfg := loadWithConfigs(t, "", "[tool]\nmemory = \"fresh\"\n", nil)
	if cfg.Tool.Memory != ToolMemoryFresh {
		t.Errorf("Tool.Memory = %q, want %q from the project config", cfg.Tool.Memory, ToolMemoryFresh)
	}
}
