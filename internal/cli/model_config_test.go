package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mensfeld/coi/internal/config"
)

// sandboxEnvForProjectConfig writes a project .coi/config.toml with the given
// body, resolves it through the real config pipeline (default config +
// OverlayProjectConfig, which parses the TOML, applies untrusted-scope
// sanitization, and merges it), configures the tool exactly as a session launch
// does (getConfiguredTool), and returns the Claude sandbox settings' env block.
//
// That env map is what mergeJSONSettings writes verbatim into the container's
// settings.json, so asserting on it is an end-to-end check of the config→tool→
// settings wiring without needing a container.
func sandboxEnvForProjectConfig(t *testing.T, tomlBody string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	coiDir := filepath.Join(dir, ".coi")
	if err := os.MkdirAll(coiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte(tomlBody), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.GetDefaultConfig()
	if err := cfg.OverlayProjectConfig(dir); err != nil {
		t.Fatalf("OverlayProjectConfig: %v", err)
	}

	tl, err := getConfiguredTool(cfg)
	if err != nil {
		t.Fatalf("getConfiguredTool: %v", err)
	}
	env, _ := tl.GetSandboxSettings()["env"].(map[string]string)
	return env
}

// TestToolClaudeModel_InjectedFromConfig is the integration guard for the model
// wiring introduced by moving `model` under [tool.claude]: a configured model
// must reach Claude Code as ANTHROPIC_MODEL in the sandbox settings. It drives
// the real chain (TOML file → config resolution → getConfiguredTool →
// GetSandboxSettings), so a break anywhere along it fails red — unlike the
// tool-level unit tests, which call SetModel directly and can't catch a
// resolution/apply regression.
func TestToolClaudeModel_InjectedFromConfig(t *testing.T) {
	env := sandboxEnvForProjectConfig(t,
		"[tool]\nname = \"claude\"\n\n[tool.claude]\nmodel = \"claude-opus-4-8\"\n")
	if env["ANTHROPIC_MODEL"] != "claude-opus-4-8" {
		t.Errorf("expected ANTHROPIC_MODEL=claude-opus-4-8 in sandbox env, got %q (env=%v)",
			env["ANTHROPIC_MODEL"], env)
	}
}

// TestToolClaudeModel_AliasPassedThrough proves a short alias is delivered
// verbatim (confirmed to resolve to the aliased model via ANTHROPIC_MODEL).
func TestToolClaudeModel_AliasPassedThrough(t *testing.T) {
	env := sandboxEnvForProjectConfig(t, "[tool.claude]\nmodel = \"opus\"\n")
	if env["ANTHROPIC_MODEL"] != "opus" {
		t.Errorf("expected ANTHROPIC_MODEL=opus (alias passed through verbatim), got %q",
			env["ANTHROPIC_MODEL"])
	}
}

// TestToolClaudeModel_AbsentWhenUnset proves nothing is injected when the model
// is not configured, so Claude Code uses its own default.
func TestToolClaudeModel_AbsentWhenUnset(t *testing.T) {
	env := sandboxEnvForProjectConfig(t, "[tool]\nname = \"claude\"\n")
	if v, ok := env["ANTHROPIC_MODEL"]; ok {
		t.Errorf("expected no ANTHROPIC_MODEL when [tool.claude] model is unset, got %q", v)
	}
}

// TestToolClaudeModel_CoexistsWithEffort proves the model and effort knobs share
// the sandbox env block without clobbering each other (both are set from config).
func TestToolClaudeModel_CoexistsWithEffort(t *testing.T) {
	env := sandboxEnvForProjectConfig(t,
		"[tool.claude]\nmodel = \"claude-opus-4-8\"\neffort_level = \"high\"\n")
	if env["ANTHROPIC_MODEL"] != "claude-opus-4-8" {
		t.Errorf("expected ANTHROPIC_MODEL=claude-opus-4-8, got %q", env["ANTHROPIC_MODEL"])
	}
	if env["CLAUDE_CODE_EFFORT_LEVEL"] != "high" {
		t.Errorf("expected CLAUDE_CODE_EFFORT_LEVEL=high, got %q", env["CLAUDE_CODE_EFFORT_LEVEL"])
	}
}
