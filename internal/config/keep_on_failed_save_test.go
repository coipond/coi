package config

import (
	"testing"

	"github.com/BurntSushi/toml"

	coischema "github.com/coipond/coi/schema"
)

func TestKeepOnFailedSave_DefaultsOff(t *testing.T) {
	cfg := GetDefaultConfig()
	if cfg.Container.KeepsOnFailedSave() {
		t.Error("keep_on_failed_save should default to off")
	}
}

func TestKeepOnFailedSave_ParsesFromTOML(t *testing.T) {
	var c Config
	if _, err := toml.Decode("[container]\nkeep_on_failed_save = true\n", &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !c.Container.KeepsOnFailedSave() {
		t.Error("keep_on_failed_save = true not parsed")
	}
}

func TestKeepOnFailedSave_AppliedFromProfile(t *testing.T) {
	on := true
	cfg := GetDefaultConfig()
	cfg.Profiles = map[string]ProfileConfig{
		"keep": {Container: ContainerConfig{KeepOnFailedSave: &on}},
	}
	if err := cfg.ApplyProfile("keep"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	if !cfg.Container.KeepsOnFailedSave() {
		t.Error("profile keep_on_failed_save not applied")
	}
}

func TestKeepOnFailedSave_ProfileSchemaAccepts(t *testing.T) {
	if err := coischema.ValidateProfileMap(map[string]any{
		"container": map[string]any{"keep_on_failed_save": true},
	}); err != nil {
		t.Errorf("profile with keep_on_failed_save rejected: %v", err)
	}
}
