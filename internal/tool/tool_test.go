package tool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeToolBasics(t *testing.T) {
	tool := NewClaude()

	if tool.Name() != "claude" {
		t.Errorf("Expected name 'claude', got '%s'", tool.Name())
	}

	if tool.Binary() != "claude" {
		t.Errorf("Expected binary 'claude', got '%s'", tool.Binary())
	}

	if tool.ConfigDirName() != ".claude" {
		t.Errorf("Expected config dir '.claude', got '%s'", tool.ConfigDirName())
	}

	if tool.SessionsDirName() != "sessions-claude" {
		t.Errorf("Expected sessions dir 'sessions-claude', got '%s'", tool.SessionsDirName())
	}
}

func TestClaudeBuildCommand_NewSession(t *testing.T) {
	tool := NewClaude()
	sessionID := "test-session-123"

	cmd := tool.BuildCommand(sessionID, false, "")

	expected := []string{"claude", "--verbose", "--permission-mode", "bypassPermissions", "--session-id", "test-session-123"}

	if len(cmd) != len(expected) {
		t.Fatalf("Expected %d args, got %d: %v", len(expected), len(cmd), cmd)
	}

	for i, arg := range expected {
		if cmd[i] != arg {
			t.Errorf("Arg[%d]: expected '%s', got '%s'", i, arg, cmd[i])
		}
	}
}

func TestClaudeBuildCommand_ResumeWithID(t *testing.T) {
	tool := NewClaude()
	resumeSessionID := "cli-session-456"

	cmd := tool.BuildCommand("", true, resumeSessionID)

	// Should contain --resume with the session ID
	if !contains(cmd, "--resume") {
		t.Errorf("Expected command to contain '--resume', got: %v", cmd)
	}

	if !contains(cmd, resumeSessionID) {
		t.Errorf("Expected command to contain '%s', got: %v", resumeSessionID, cmd)
	}

	// Should still have permission flags
	if !contains(cmd, "--permission-mode") {
		t.Errorf("Expected command to contain '--permission-mode', got: %v", cmd)
	}

	if !contains(cmd, "bypassPermissions") {
		t.Errorf("Expected command to contain 'bypassPermissions', got: %v", cmd)
	}
}

func TestClaudeBuildCommand_ResumeWithoutID(t *testing.T) {
	tool := NewClaude()

	cmd := tool.BuildCommand("", true, "")

	// Should contain --resume without a specific ID
	if !contains(cmd, "--resume") {
		t.Errorf("Expected command to contain '--resume', got: %v", cmd)
	}

	// Should have exactly one --resume (not followed by an ID)
	resumeIdx := indexOf(cmd, "--resume")
	if resumeIdx == -1 {
		t.Fatal("--resume not found in command")
	}

	// If there's a next arg, it should be a flag (starting with -) not a session ID
	if resumeIdx+1 < len(cmd) {
		nextArg := cmd[resumeIdx+1]
		if !strings.HasPrefix(nextArg, "-") && nextArg != "claude" {
			t.Errorf("Expected --resume to be standalone, but next arg is '%s'", nextArg)
		}
	}
}

func TestClaudeDiscoverSessionID_ValidSession(t *testing.T) {
	tool := NewClaude()

	// Create temporary directory structure
	tmpDir := t.TempDir()
	projectsDir := filepath.Join(tmpDir, "projects", "-workspace")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create a .jsonl file (Claude session file)
	sessionID := "test-session-abc123"
	sessionFile := filepath.Join(projectsDir, sessionID+".jsonl")
	if err := os.WriteFile(sessionFile, []byte("{}"), 0o644); err != nil {
		t.Fatalf("Failed to create session file: %v", err)
	}

	// Test discovery
	discovered := tool.DiscoverSessionID(tmpDir)
	if discovered != sessionID {
		t.Errorf("Expected session ID '%s', got '%s'", sessionID, discovered)
	}
}

func TestClaudeDiscoverSessionID_NoSession(t *testing.T) {
	tool := NewClaude()

	// Create empty directory structure
	tmpDir := t.TempDir()
	projectsDir := filepath.Join(tmpDir, "projects", "-workspace")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Test discovery with no session files
	discovered := tool.DiscoverSessionID(tmpDir)
	if discovered != "" {
		t.Errorf("Expected empty session ID, got '%s'", discovered)
	}
}

func TestClaudeDiscoverSessionID_NonExistentDir(t *testing.T) {
	tool := NewClaude()

	// Test discovery with non-existent directory
	discovered := tool.DiscoverSessionID("/nonexistent/path")
	if discovered != "" {
		t.Errorf("Expected empty session ID for non-existent path, got '%s'", discovered)
	}
}

func TestClaudeGetSandboxSettings(t *testing.T) {
	tool := NewClaude()

	settings := tool.GetSandboxSettings()

	// Check required settings
	if settings["allowDangerouslySkipPermissions"] != true {
		t.Error("Expected allowDangerouslySkipPermissions to be true")
	}

	if settings["bypassPermissionsModeAccepted"] != true {
		t.Error("Expected bypassPermissionsModeAccepted to be true")
	}

	// Check permissions map
	permissions, ok := settings["permissions"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected permissions to be map[string]interface{}")
	}

	if permissions["defaultMode"] != "bypassPermissions" {
		t.Errorf("Expected defaultMode 'bypassPermissions', got '%v'", permissions["defaultMode"])
	}

	// skipDangerousModePermissionPrompt must be top-level: Claude Code only reads it
	// there, not nested under "permissions" (mensfeld/coi#649).
	if settings["skipDangerousModePermissionPrompt"] != true {
		t.Errorf("Expected top-level skipDangerousModePermissionPrompt true, got '%v'", settings["skipDangerousModePermissionPrompt"])
	}
	if _, ok := permissions["skipDangerousModePermissionPrompt"]; ok {
		t.Error("Expected skipDangerousModePermissionPrompt to not be nested under permissions")
	}

	// Prompt suppression flags must always be present
	if settings["effortLevelAccepted"] != true {
		t.Error("Expected effortLevelAccepted to be true")
	}
	if settings["hasSeenEffortPrompt"] != true {
		t.Error("Expected hasSeenEffortPrompt to be true")
	}
	if settings["effortCalloutDismissed"] != true {
		t.Error("Expected effortCalloutDismissed to be true")
	}

	// When effort level is not configured, effortLevel and env must be absent
	if _, ok := settings["effortLevel"]; ok {
		t.Error("Expected effortLevel to be absent when not configured")
	}
	if _, ok := settings["env"]; ok {
		t.Error("Expected env (CLAUDE_CODE_EFFORT_LEVEL) to be absent when effort level not configured")
	}
}

func TestClaudeSetEffortLevel(t *testing.T) {
	twel, ok := NewClaude().(ToolWithEffortLevel)
	if !ok {
		t.Fatal("Claude tool should implement ToolWithEffortLevel")
	}

	for _, level := range []string{"low", "medium", "high", "xhigh", "max", "auto"} {
		twel.SetEffortLevel(level)
		settings := twel.(interface{ GetSandboxSettings() map[string]interface{} }).GetSandboxSettings()

		if settings["effortLevel"] != level {
			t.Errorf("level %q: expected effortLevel %q, got %v", level, level, settings["effortLevel"])
		}
		env, ok := settings["env"].(map[string]string)
		if !ok {
			t.Fatalf("level %q: expected env to be map[string]string", level)
		}
		if env["CLAUDE_CODE_EFFORT_LEVEL"] != level {
			t.Errorf("level %q: expected CLAUDE_CODE_EFFORT_LEVEL %q, got %q", level, level, env["CLAUDE_CODE_EFFORT_LEVEL"])
		}
	}
}

func TestClaudeEffortLevelDefault(t *testing.T) {
	// When effortLevel is not set, effortLevel and CLAUDE_CODE_EFFORT_LEVEL must be absent
	// so the user can change the effort level interactively inside Claude.
	tool := NewClaude()
	settings := tool.GetSandboxSettings()

	if _, ok := settings["effortLevel"]; ok {
		t.Error("Expected effortLevel to be absent when not configured — user should control it interactively")
	}
	if _, ok := settings["env"]; ok {
		t.Error("Expected env to be absent when effort level not configured")
	}
}

func TestClaudeSetModel(t *testing.T) {
	twm, ok := NewClaude().(ToolWithModel)
	if !ok {
		t.Fatal("Claude tool should implement ToolWithModel")
	}

	for _, model := range []string{"opus", "sonnet", "claude-opus-4-8"} {
		twm.SetModel(model)
		settings := twm.(interface {
			GetSandboxSettings() map[string]interface{}
		}).GetSandboxSettings()

		env, ok := settings["env"].(map[string]string)
		if !ok {
			t.Fatalf("model %q: expected env to be map[string]string", model)
		}
		if env["ANTHROPIC_MODEL"] != model {
			t.Errorf("model %q: expected ANTHROPIC_MODEL %q, got %q", model, model, env["ANTHROPIC_MODEL"])
		}
	}
}

func TestClaudeModelDefault(t *testing.T) {
	// When model is not set, ANTHROPIC_MODEL must be absent so Claude Code uses
	// its own default. With no effort level either, the env block is absent.
	settings := NewClaude().GetSandboxSettings()
	if _, ok := settings["env"]; ok {
		t.Error("Expected env to be absent when neither model nor effort level configured")
	}
}

func TestClaudeModelAndEffortCoexist(t *testing.T) {
	// Both knobs deliver via the same settings["env"] map; setting one must not
	// clobber the other.
	c := NewClaude()
	c.(ToolWithEffortLevel).SetEffortLevel("high")
	c.(ToolWithModel).SetModel("opus")

	env, ok := c.GetSandboxSettings()["env"].(map[string]string)
	if !ok {
		t.Fatal("expected env to be map[string]string")
	}
	if env["CLAUDE_CODE_EFFORT_LEVEL"] != "high" {
		t.Errorf("expected CLAUDE_CODE_EFFORT_LEVEL 'high', got %q", env["CLAUDE_CODE_EFFORT_LEVEL"])
	}
	if env["ANTHROPIC_MODEL"] != "opus" {
		t.Errorf("expected ANTHROPIC_MODEL 'opus', got %q", env["ANTHROPIC_MODEL"])
	}
}

// Claude must expose model/effort via GetContainerEnv too, so session setup can
// persist them as container-level environment.* that any exec inherits (#744).
func TestClaudeGetContainerEnv(t *testing.T) {
	twce, ok := NewClaude().(ToolWithContainerEnv)
	if !ok {
		t.Fatal("Claude tool should implement ToolWithContainerEnv")
	}

	// Nothing configured -> no env (tool keeps its own defaults).
	if env := twce.GetContainerEnv("/workspace"); len(env) != 0 {
		t.Errorf("unconfigured Claude should return no container env, got %v", env)
	}

	twce.(ToolWithModel).SetModel("opus")
	twce.(ToolWithEffortLevel).SetEffortLevel("high")
	env := twce.GetContainerEnv("/workspace")
	if env["ANTHROPIC_MODEL"] != "opus" {
		t.Errorf("ANTHROPIC_MODEL = %q, want opus", env["ANTHROPIC_MODEL"])
	}
	if env["CLAUDE_CODE_EFFORT_LEVEL"] != "high" {
		t.Errorf("CLAUDE_CODE_EFFORT_LEVEL = %q, want high", env["CLAUDE_CODE_EFFORT_LEVEL"])
	}

	// Only model set -> only ANTHROPIC_MODEL, no effort key.
	only := NewClaude()
	only.(ToolWithModel).SetModel("sonnet")
	oenv := only.(ToolWithContainerEnv).GetContainerEnv("/workspace")
	if oenv["ANTHROPIC_MODEL"] != "sonnet" {
		t.Errorf("ANTHROPIC_MODEL = %q, want sonnet", oenv["ANTHROPIC_MODEL"])
	}
	if _, ok := oenv["CLAUDE_CODE_EFFORT_LEVEL"]; ok {
		t.Error("CLAUDE_CODE_EFFORT_LEVEL must be absent when effort not configured")
	}
}

func TestClaudeToolConfigDirFiles(t *testing.T) {
	tool := NewClaude()
	tcf, ok := tool.(ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("ClaudeTool does not implement ToolWithConfigDirFiles")
	}

	// EssentialConfigFiles
	files := tcf.EssentialConfigFiles()
	expected := []string{".credentials.json", "config.yml", "settings.json", "CLAUDE.md"}
	if len(files) != len(expected) {
		t.Fatalf("EssentialConfigFiles() = %v, want %v", files, expected)
	}
	for i, f := range files {
		if f != expected[i] {
			t.Errorf("EssentialConfigFiles()[%d] = %q, want %q", i, f, expected[i])
		}
	}

	// SandboxSettingsFileName
	if tcf.SandboxSettingsFileName() != "settings.json" {
		t.Errorf("SandboxSettingsFileName() = %q, want %q", tcf.SandboxSettingsFileName(), "settings.json")
	}

	// StateConfigFileName
	if tcf.StateConfigFileName() != ".claude.json" {
		t.Errorf("StateConfigFileName() = %q, want %q", tcf.StateConfigFileName(), ".claude.json")
	}

	// AlwaysSetupConfig
	if tcf.AlwaysSetupConfig() {
		t.Error("AlwaysSetupConfig() = true, want false")
	}
}

func TestRegistryGet_Claude(t *testing.T) {
	tool, err := Get("claude")
	if err != nil {
		t.Fatalf("Expected to get claude tool, got error: %v", err)
	}

	if tool.Name() != "claude" {
		t.Errorf("Expected tool name 'claude', got '%s'", tool.Name())
	}
}

func TestRegistryGet_Unknown(t *testing.T) {
	_, err := Get("unknown-tool")
	if err == nil {
		t.Error("Expected error for unknown tool, got nil")
	}

	expectedMsg := "unknown tool"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got: %v", expectedMsg, err)
	}
}

func TestRegistryGetDefault(t *testing.T) {
	tool := GetDefault()

	if tool == nil {
		t.Fatal("Expected tool, got nil")
	}

	if tool.Name() != "claude" {
		t.Errorf("Expected default tool to be 'claude', got '%s'", tool.Name())
	}
}

func TestClaudeSetPermissionMode_Interface(t *testing.T) {
	tool := NewClaude()

	// Verify ClaudeTool implements ToolWithPermissionMode
	twpm, ok := tool.(ToolWithPermissionMode)
	if !ok {
		t.Fatal("Claude tool should implement ToolWithPermissionMode")
	}

	// Verify the method works without panic
	twpm.SetPermissionMode("interactive")
}

func TestClaudeBuildCommand_InteractiveMode(t *testing.T) {
	ct := &ClaudeTool{permissionMode: "interactive"}
	sessionID := "test-session-123"

	cmd := ct.BuildCommand(sessionID, false, "")

	// Should have --verbose and --session-id but NOT --permission-mode/bypassPermissions
	if !contains(cmd, "--verbose") {
		t.Error("Expected command to contain '--verbose'")
	}
	if !contains(cmd, "--session-id") {
		t.Error("Expected command to contain '--session-id'")
	}
	if !contains(cmd, sessionID) {
		t.Errorf("Expected command to contain '%s'", sessionID)
	}
	if contains(cmd, "--permission-mode") {
		t.Error("Expected command NOT to contain '--permission-mode' in interactive mode")
	}
	if contains(cmd, "bypassPermissions") {
		t.Error("Expected command NOT to contain 'bypassPermissions' in interactive mode")
	}
}

func TestClaudeBuildCommand_BypassModeExplicit(t *testing.T) {
	ct := &ClaudeTool{permissionMode: "bypass"}
	sessionID := "test-session-123"

	cmd := ct.BuildCommand(sessionID, false, "")

	// Explicit "bypass" should behave like default (include --permission-mode bypassPermissions)
	if !contains(cmd, "--permission-mode") {
		t.Error("Expected command to contain '--permission-mode' in bypass mode")
	}
	if !contains(cmd, "bypassPermissions") {
		t.Error("Expected command to contain 'bypassPermissions' in bypass mode")
	}
}

func TestClaudeGetSandboxSettings_InteractiveMode(t *testing.T) {
	ct := &ClaudeTool{permissionMode: "interactive"}

	settings := ct.GetSandboxSettings()

	// Should NOT have bypass permission keys
	if _, ok := settings["allowDangerouslySkipPermissions"]; ok {
		t.Error("Expected no 'allowDangerouslySkipPermissions' key in interactive mode")
	}
	if _, ok := settings["bypassPermissionsModeAccepted"]; ok {
		t.Error("Expected no 'bypassPermissionsModeAccepted' key in interactive mode")
	}
	if _, ok := settings["permissions"]; ok {
		t.Error("Expected no 'permissions' key in interactive mode")
	}

	// Prompt suppression flags must always be present
	if settings["effortLevelAccepted"] != true {
		t.Error("Expected effortLevelAccepted to be true")
	}
	if settings["hasSeenEffortPrompt"] != true {
		t.Error("Expected hasSeenEffortPrompt to be true")
	}
	if settings["effortCalloutDismissed"] != true {
		t.Error("Expected effortCalloutDismissed to be true")
	}

	// Effort level not configured — must not be locked
	if _, ok := settings["effortLevel"]; ok {
		t.Error("Expected effortLevel to be absent when not configured")
	}
	if _, ok := settings["env"]; ok {
		t.Error("Expected env to be absent when effort level not configured")
	}
}

func TestClaudeGetSandboxSettings_BypassModeDefault(t *testing.T) {
	ct := &ClaudeTool{} // Empty permissionMode = default bypass

	settings := ct.GetSandboxSettings()

	// Should have bypass permission keys (default behavior)
	if settings["allowDangerouslySkipPermissions"] != true {
		t.Error("Expected allowDangerouslySkipPermissions to be true")
	}
	if settings["bypassPermissionsModeAccepted"] != true {
		t.Error("Expected bypassPermissionsModeAccepted to be true")
	}

	permissions, ok := settings["permissions"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected permissions to be map[string]interface{}")
	}
	if permissions["defaultMode"] != "bypassPermissions" {
		t.Errorf("Expected defaultMode 'bypassPermissions', got '%v'", permissions["defaultMode"])
	}
	if settings["skipDangerousModePermissionPrompt"] != true {
		t.Errorf("Expected top-level skipDangerousModePermissionPrompt true, got '%v'", settings["skipDangerousModePermissionPrompt"])
	}
	if _, ok := permissions["skipDangerousModePermissionPrompt"]; ok {
		t.Error("Expected skipDangerousModePermissionPrompt to not be nested under permissions")
	}

	// Effort level not configured — must not be locked
	if _, ok := settings["effortLevel"]; ok {
		t.Error("Expected effortLevel to be absent when not configured")
	}
}

func TestClaudeBuildCommand_ResumeInteractiveMode(t *testing.T) {
	ct := &ClaudeTool{permissionMode: "interactive"}
	resumeSessionID := "cli-session-456"

	cmd := ct.BuildCommand("", true, resumeSessionID)

	// Should have --resume with session ID
	if !contains(cmd, "--resume") {
		t.Error("Expected command to contain '--resume'")
	}
	if !contains(cmd, resumeSessionID) {
		t.Errorf("Expected command to contain '%s'", resumeSessionID)
	}

	// Should NOT have permission flags
	if contains(cmd, "--permission-mode") {
		t.Error("Expected command NOT to contain '--permission-mode' in interactive mode")
	}
	if contains(cmd, "bypassPermissions") {
		t.Error("Expected command NOT to contain 'bypassPermissions' in interactive mode")
	}

	// Should still have --verbose
	if !contains(cmd, "--verbose") {
		t.Error("Expected command to contain '--verbose'")
	}
}

func TestClaudeTool_AutoContextFile(t *testing.T) {
	tool := NewClaude()
	acf, ok := tool.(ToolWithAutoContextFile)
	if !ok {
		t.Fatal("ClaudeTool should implement ToolWithAutoContextFile")
	}

	path := acf.AutoContextFile()
	if path != ".claude/CLAUDE.md" {
		t.Errorf("AutoContextFile() = %q, want %q", path, ".claude/CLAUDE.md")
	}
}

func TestClaudeTool_EssentialConfigFiles_IncludesCLAUDEMD(t *testing.T) {
	tool := NewClaude()
	tcf, ok := tool.(ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("ClaudeTool does not implement ToolWithConfigDirFiles")
	}

	files := tcf.EssentialConfigFiles()
	found := false
	for _, f := range files {
		if f == "CLAUDE.md" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("EssentialConfigFiles() = %v, does not include 'CLAUDE.md'", files)
	}
}

func TestRenderContextFileContent(t *testing.T) {
	info := ContextInfo{
		WorkspacePath:     "/workspace",
		HomeDir:           "/home/code",
		Persistent:        false,
		NetworkMode:       "restricted",
		SSHAgentForwarded: true,
		RunAsRoot:         false,
		Architecture:      "amd64",
		ProtectedPaths:    []string{".git/hooks", ".vscode"},
		Timezone:          "America/New_York",
		ToolName:          "claude",
		ContainerName:     "coi-test-1",
	}

	content := RenderContextFileContent(info)

	// Check that key sections are present
	checks := []struct {
		name   string
		substr string
	}{
		{"workspace path", "/workspace"},
		{"home dir", "/home/code"},
		{"ephemeral mode", "Ephemeral"},
		{"restricted network", "Restricted"},
		{"network limitation", "local/private networks are blocked"},
		{"ssh forwarded", "Forwarded from host"},
		{"non-root user", "Non-root user"},
		{"Coi header", "COI Sandbox Environment"},
		{"full root access", "full root"},
		{"docker available", "Docker (Docker-in-Docker)"},
		{"OS info", "Ubuntu"},
		{"architecture", "amd64"},
		{"docker row", "Docker-in-Docker"},
		{"troubleshooting section", "Troubleshooting"},
		{"limitations section", "Limitations"},
		{"protected paths", ".git/hooks, .vscode"},
		{"ephemeral warning", "System-level changes"},
		{"timezone", "America/New_York"},
		{"tool name", "claude"},
		{"container name", "coi-test-1"},
		{"autonomous operation section", "Autonomous Operation"},
		{"never ask confirmation", "Never ask for confirmation"},
		{"act autonomously guidance", "expected to act, not ask"},
		{"git configuration section", "Git Configuration"},
		{"git ssh recommendation", "Use SSH for git operations"},
		{"git identity warning", `NEVER fabricate`},
	}

	for _, check := range checks {
		if !strings.Contains(content, check.substr) {
			t.Errorf("RenderContextFileContent() missing %s (expected substring %q)", check.name, check.substr)
		}
	}
}

// When Docker is disabled (docker=false or reduce_kernel_surface=true), the
// context must NOT advertise Docker-in-Docker the agent can't use — otherwise
// it burns turns debugging a dockerd that cannot start (finding: sandbox
// context Docker desc).
func TestRenderContextFileContent_DockerUnavailable(t *testing.T) {
	info := ContextInfo{
		WorkspacePath:     "/workspace",
		HomeDir:           "/home/code",
		NetworkMode:       "restricted",
		DockerUnavailable: true,
	}
	content := RenderContextFileContent(info)

	if strings.Contains(content, "Docker-in-Docker") {
		t.Error("hardened context must not advertise Docker-in-Docker")
	}
	if !strings.Contains(content, "Not available") {
		t.Errorf("Docker row should say Not available, got:\n%s", content)
	}
	// The pre-installed-tools line and the docker troubleshooting bullet must
	// be gated out too.
	if strings.Contains(content, "Docker not responding") {
		t.Error("hardened context must omit the docker troubleshooting bullet")
	}

	// JSON contract must report it too.
	jsonStr, err := RenderContextFileJSON(info)
	if err != nil {
		t.Fatalf("RenderContextFileJSON: %v", err)
	}
	if !strings.Contains(jsonStr, "\"docker_available\": false") {
		t.Errorf("JSON should report docker_available:false, got:\n%s", jsonStr)
	}

	// Default (zero value) still advertises Docker — back-compat.
	def := RenderContextFileContent(ContextInfo{WorkspacePath: "/w", HomeDir: "/h", NetworkMode: "open"})
	if !strings.Contains(def, "Docker-in-Docker") {
		t.Error("default context should still advertise Docker-in-Docker")
	}
}

func TestRenderContextFileContent_Persistent(t *testing.T) {
	info := ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       "/root",
		Persistent:    true,
		NetworkMode:   "open",
		RunAsRoot:     true,
	}

	content := RenderContextFileContent(info)

	if !strings.Contains(content, "Persistent") {
		t.Error("Expected 'Persistent' in content for persistent mode")
	}
	if !strings.Contains(content, "Open") {
		t.Error("Expected 'Open' in content for open network mode")
	}
	if !strings.Contains(content, "Root user") {
		t.Error("Expected 'Root user' in content for root mode")
	}
	// Persistent mode should NOT warn about system-level changes being lost
	if strings.Contains(content, "System-level changes") {
		t.Error("Persistent mode should not contain ephemeral warning about system-level changes")
	}
}

func TestRenderContextFileContent_AllNetworkModes(t *testing.T) {
	tests := []struct {
		mode              string
		expected          string
		hasLimitation     bool
		limitationContain string
	}{
		{"restricted", "Restricted", true, "local/private networks are blocked"},
		{"open", "Open", false, ""},
		{"allowlist", "Allowlist", true, "pre-approved domains"},
		{"", "Default", false, ""},
	}

	for _, tt := range tests {
		info := ContextInfo{
			WorkspacePath: "/workspace",
			HomeDir:       "/home/code",
			NetworkMode:   tt.mode,
		}
		content := RenderContextFileContent(info)
		if !strings.Contains(content, tt.expected) {
			t.Errorf("NetworkMode %q: expected content to contain %q", tt.mode, tt.expected)
		}
		if tt.hasLimitation {
			if !strings.Contains(content, tt.limitationContain) {
				t.Errorf("NetworkMode %q: expected limitation containing %q", tt.mode, tt.limitationContain)
			}
		}
	}
}

// The generated sandbox context MUST surface the fine-grained egress controls
// (allowed_ports, dns_servers, allowlist domains) so the agent knows what it can
// and cannot reach. These are injected into the tool's system prompt via the
// auto-context file, so a gap here means the agent dials blocked ports/resolvers
// blindly.
func TestRenderContextFileContent_EgressControls(t *testing.T) {
	t.Run("allowed_ports surfaced", func(t *testing.T) {
		content := RenderContextFileContent(ContextInfo{
			WorkspacePath: "/workspace", HomeDir: "/home/code",
			NetworkMode: "restricted", AllowedPorts: []int{80, 443},
		})
		for _, want := range []string{"restricted to destination port(s) 80, 443", "egress-filtered"} {
			if !strings.Contains(content, want) {
				t.Errorf("allowed_ports: expected context to contain %q\n---\n%s", want, content)
			}
		}
	})

	t.Run("dns_servers surfaced", func(t *testing.T) {
		content := RenderContextFileContent(ContextInfo{
			WorkspacePath: "/workspace", HomeDir: "/home/code",
			NetworkMode: "restricted", DNSServers: []string{"192.168.1.2"},
		})
		if !strings.Contains(content, "DNS is pinned to 192.168.1.2") {
			t.Errorf("dns_servers: expected pinned-resolver note, got:\n%s", content)
		}
	})

	t.Run("allowlist domains enumerated", func(t *testing.T) {
		content := RenderContextFileContent(ContextInfo{
			WorkspacePath: "/workspace", HomeDir: "/home/code",
			NetworkMode: "allowlist", AllowedDomains: []string{"api.anthropic.com", "registry.npmjs.org"},
		})
		for _, want := range []string{"api.anthropic.com", "registry.npmjs.org", "only reachable outbound destinations"} {
			if !strings.Contains(content, want) {
				t.Errorf("allowlist domains: expected context to contain %q", want)
			}
		}
	})

	t.Run("combined ports+dns", func(t *testing.T) {
		content := RenderContextFileContent(ContextInfo{
			WorkspacePath: "/workspace", HomeDir: "/home/code",
			NetworkMode: "restricted", AllowedPorts: []int{443}, DNSServers: []string{"10.0.0.53"},
		})
		if !strings.Contains(content, "destination port(s) 443") || !strings.Contains(content, "DNS is pinned to 10.0.0.53") {
			t.Errorf("combined: expected both port cap and DNS pin in context:\n%s", content)
		}
	})

	t.Run("no controls => no egress-filtered note", func(t *testing.T) {
		// Parity: without the new controls the context must not gain the egress note,
		// so existing configs render unchanged.
		content := RenderContextFileContent(ContextInfo{
			WorkspacePath: "/workspace", HomeDir: "/home/code", NetworkMode: "open",
		})
		if strings.Contains(content, "egress-filtered") || strings.Contains(content, "DNS is pinned") {
			t.Errorf("open mode with no controls should not mention egress filtering:\n%s", content)
		}
	})

	t.Run("open mode does not claim a cap it never enforces", func(t *testing.T) {
		// Open mode installs a blanket accept: allowed_ports/dns_servers are inert.
		// The context must not tell the agent egress is filtered, or it would waste
		// turns avoiding ports/resolvers that are actually reachable.
		content := RenderContextFileContent(ContextInfo{
			WorkspacePath: "/workspace", HomeDir: "/home/code",
			NetworkMode: "open", AllowedPorts: []int{80, 443}, DNSServers: []string{"192.168.1.2"},
		})
		for _, unwanted := range []string{"restricted to destination port(s)", "DNS is pinned", "egress-filtered"} {
			if strings.Contains(content, unwanted) {
				t.Errorf("open mode must not surface %q (it is not enforced):\n%s", unwanted, content)
			}
		}
	})

	t.Run("allowlist mode does not claim DNS pinning", func(t *testing.T) {
		// dns_servers is rejected at setup in allowlist mode (all DNS is blocked and
		// /etc/hosts is authoritative), so the context must not advertise a pin.
		// allowed_ports, however, IS enforced in allowlist mode and should show.
		content := RenderContextFileContent(ContextInfo{
			WorkspacePath: "/workspace", HomeDir: "/home/code",
			NetworkMode: "allowlist", AllowedPorts: []int{443}, DNSServers: []string{"192.168.1.2"},
			AllowedDomains: []string{"api.anthropic.com"},
		})
		if strings.Contains(content, "DNS is pinned") {
			t.Errorf("allowlist mode blocks all DNS; must not claim a resolver pin:\n%s", content)
		}
		if !strings.Contains(content, "destination port(s) 443") {
			t.Errorf("allowlist mode enforces allowed_ports; expected it surfaced:\n%s", content)
		}
	})
}

func TestRenderContextFileContent_NoProtectedPaths(t *testing.T) {
	info := ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
	}
	content := RenderContextFileContent(info)
	if strings.Contains(content, "Protected paths") {
		t.Error("Should not contain protected paths section when none configured")
	}
}

func TestRenderContextFileContent_WithResourceLimits(t *testing.T) {
	info := ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
		CPULimit:      "2",
		MemoryLimit:   "4GiB",
	}
	content := RenderContextFileContent(info)
	if !strings.Contains(content, "Resource limits") {
		t.Error("Expected 'Resource limits' in content when CPU and memory limits are set")
	}
	if !strings.Contains(content, "2 CPUs") {
		t.Error("Expected '2 CPUs' in resource limits")
	}
	if !strings.Contains(content, "4GiB memory") {
		t.Error("Expected '4GiB memory' in resource limits")
	}
}

func TestRenderContextFileContent_WithMaxDuration(t *testing.T) {
	info := ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
		MaxDuration:   "2h",
	}
	content := RenderContextFileContent(info)
	if !strings.Contains(content, "Session timeout") {
		t.Error("Expected 'Session timeout' in content when max duration is set")
	}
	if !strings.Contains(content, "2h") {
		t.Error("Expected '2h' in session timeout")
	}
}

func TestRenderContextFileContent_WithExtraMounts(t *testing.T) {
	info := ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
		ExtraMounts:   []MountInfo{{ContainerPath: "/data"}, {ContainerPath: "/config"}},
	}
	content := RenderContextFileContent(info)
	if !strings.Contains(content, "Additional Mounts") {
		t.Error("Expected 'Additional Mounts' section when extra mounts are set")
	}
	if !strings.Contains(content, "/data") {
		t.Error("Expected '/data' in extra mounts")
	}
	if !strings.Contains(content, "/config") {
		t.Error("Expected '/config' in extra mounts")
	}
}

func TestRenderContextFileContent_DefaultTimezone(t *testing.T) {
	info := ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
	}
	content := RenderContextFileContent(info)
	if !strings.Contains(content, "UTC") {
		t.Error("Expected 'UTC' as default timezone")
	}
}

func TestRenderContextFileContent_NoOptionalSections(t *testing.T) {
	info := ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
	}
	content := RenderContextFileContent(info)
	if strings.Contains(content, "Resource limits") {
		t.Error("Should not contain 'Resource limits' when no limits configured")
	}
	if strings.Contains(content, "Session timeout") {
		t.Error("Should not contain 'Session timeout' when no max duration configured")
	}
	if strings.Contains(content, "Additional Mounts") {
		t.Error("Should not contain 'Additional Mounts' when no extra mounts configured")
	}
}

func TestRenderContextFileContent_GitAuthHints_SSHOnly(t *testing.T) {
	info := ContextInfo{
		WorkspacePath:     "/workspace",
		HomeDir:           "/home/code",
		SSHAgentForwarded: true,
	}
	content := RenderContextFileContent(info)

	if !strings.Contains(content, "Git Configuration") {
		t.Error("Expected 'Git Configuration' section when SSH is forwarded")
	}
	if !strings.Contains(content, "Use SSH for git operations") {
		t.Error("Expected SSH recommendation for git operations")
	}
	if !strings.Contains(content, `ssh -T -o StrictHostKeyChecking=accept-new -o BatchMode=yes "git@${ssh_host}"`) {
		t.Error("Expected ssh -T command for identity discovery")
	}
	if !strings.Contains(content, "git remote get-url origin") {
		t.Error("Expected guidance to check remote URL")
	}
	if !strings.Contains(content, "NEVER fabricate") {
		t.Error("Expected warning against fabricating git identity")
	}
	if !strings.Contains(content, "code@example.com") {
		t.Error("Expected explicit mention of forbidden code@example.com")
	}
	if strings.Contains(content, "token may have limited scope") {
		t.Error("Should not mention token scope when only SSH is available")
	}
}

func TestRenderContextFileContent_GitAuthHints_TokenOnly(t *testing.T) {
	info := ContextInfo{
		WorkspacePath:      "/workspace",
		HomeDir:            "/home/code",
		GHCLIAuthenticated: true,
	}
	content := RenderContextFileContent(info)

	if !strings.Contains(content, "Git Configuration") {
		t.Error("Expected 'Git Configuration' section when token is available")
	}
	if !strings.Contains(content, "Token-based git auth is available") {
		t.Error("Expected token-based auth description")
	}
	if !strings.Contains(content, "may have limited scope") {
		t.Error("Expected scope warning for forwarded token")
	}
	if !strings.Contains(content, "gh api user") {
		t.Error("Expected gh api command for identity discovery")
	}
	if !strings.Contains(content, "NEVER fabricate") {
		t.Error("Expected warning against fabricating git identity")
	}
	if !strings.Contains(content, "code@example.com") {
		t.Error("Expected explicit mention of forbidden code@example.com")
	}
	// GitHubCLIDesc in the environment table should also have scope warning
	if !strings.Contains(content, "token may have limited scope/permissions") {
		t.Error("Expected scope/permissions warning in GitHub CLI table row")
	}
}

func TestRenderContextFileContent_GitAuthHints_BothSSHAndToken(t *testing.T) {
	info := ContextInfo{
		WorkspacePath:      "/workspace",
		HomeDir:            "/home/code",
		SSHAgentForwarded:  true,
		GHCLIAuthenticated: true,
	}
	content := RenderContextFileContent(info)

	if !strings.Contains(content, "Git Configuration") {
		t.Error("Expected 'Git Configuration' section when both SSH and token are available")
	}
	if !strings.Contains(content, "Prefer SSH for git push/pull") {
		t.Error("Expected SSH preference recommendation")
	}
	if !strings.Contains(content, "GH_TOKEN/GITHUB_TOKEN may have limited scope") {
		t.Error("Expected token scope warning")
	}
	if !strings.Contains(content, `ssh -T -o StrictHostKeyChecking=accept-new -o BatchMode=yes "git@${ssh_host}"`) {
		t.Error("Expected ssh -T command for identity discovery")
	}
	if !strings.Contains(content, "NEVER fabricate") {
		t.Error("Expected warning against fabricating git identity")
	}
	if !strings.Contains(content, "code@example.com") {
		t.Error("Expected explicit mention of forbidden code@example.com")
	}
}

func TestRenderContextFileContent_GitAuthHints_Neither(t *testing.T) {
	info := ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
	}
	content := RenderContextFileContent(info)

	if strings.Contains(content, "Git Configuration") {
		t.Error("Should not contain 'Git Configuration' section when neither SSH nor token is available")
	}
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func indexOf(slice []string, item string) int {
	for i, s := range slice {
		if s == item {
			return i
		}
	}
	return -1
}
