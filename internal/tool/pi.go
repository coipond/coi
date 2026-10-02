package tool

import (
	"path/filepath"
)

// PiTool implements Tool for pi (https://pi.dev)
type PiTool struct {
	permissionMode  string // "bypass" (default) or "interactive" — pi has no permission gate, so this is largely a no-op
	contextFilePath string // absolute path to sandbox context file inside container (set by SetAutoContextPath)
	binary          string // [tool] binary override; empty means "pi"
}

// NewPi creates a new pi tool instance
func NewPi() Tool { return &PiTool{} }

// Name returns "pi".
func (p *PiTool) Name() string { return "pi" }

// Binary returns the executable to launch: the [tool] binary override if set,
// else "pi".
func (p *PiTool) Binary() string {
	if p.binary != "" {
		return p.binary
	}
	return "pi"
}

// SetBinary implements ToolWithBinary: the executable to launch instead of
// "pi" ([tool] binary). An empty or unsafe value leaves the default.
func (p *PiTool) SetBinary(path string) {
	if path != "" && ValidateBinary(path) == nil {
		p.binary = path
	}
}

// ConfigDirName returns the config directory for pi.
// Pi stores config in ~/.pi/agent/ (controlled by PI_CODING_AGENT_DIR).
func (p *PiTool) ConfigDirName() string { return mustBundle("pi").ConfigDir }

// SessionsDirName returns "sessions-pi".
func (p *PiTool) SessionsDirName() string { return "sessions-pi" }

// BuildCommand builds the pi launch command.
// When resume is true, passes --continue to auto-resume the last session,
// or --session <id> if a specific session ID is provided.
// Filesystem setup (symlink creation) is handled by PreLaunch(), keeping
// BuildCommand free of shell metacharacters.
func (p *PiTool) BuildCommand(sessionID string, resume bool, resumeSessionID string) []string {
	cmd := []string{p.Binary()}
	if resume {
		// Always use --continue; pi manages its own session discovery
		// in .pi-sessions/ (redirected via PI_CODING_AGENT_SESSION_DIR).
		// Coi session UUIDs are only used for metadata (slot/profile/persistent).
		cmd = append(cmd, "--continue")
	}
	return cmd
}

// PreLaunch implements ToolWithPreLaunch.
// When contextFilePath is set, creates the ~/.pi/agent/ directory and symlinks
// APPEND_SYSTEM.md to the sandbox context file. Pi appends APPEND_SYSTEM.md to
// its system prompt without replacing AGENTS.md, preserving the user's own context.
// The symlink is idempotent — no content duplication on container restart.
// Commands are returned as argv slices (no shell interpretation), preventing injection.
func (p *PiTool) PreLaunch() [][]string {
	if p.contextFilePath == "" {
		return nil
	}
	// Derive home directory from the context file path (set as <home>/SANDBOX_CONTEXT.md)
	homeDir := filepath.Dir(p.contextFilePath)
	piAgentDir := filepath.Join(homeDir, ".pi", "agent")
	linkTarget := filepath.Join(piAgentDir, "APPEND_SYSTEM.md")

	return [][]string{
		{"mkdir", "-p", piAgentDir},
		{"ln", "-sf", p.contextFilePath, linkTarget},
	}
}

// DiscoverSessionID returns "" because pi handles session discovery internally
// via --continue (sessions are stored as .jsonl files under the sessions dir).
func (p *PiTool) DiscoverSessionID(stateDir string) string { return "" }

// GetSandboxSettings returns pi's settings to inject into settings.json.
// Pi has no permission bypass system like Claude or opencode.
// Context injection is handled via PreLaunch (symlinks APPEND_SYSTEM.md).
func (p *PiTool) GetSandboxSettings() map[string]interface{} {
	return map[string]interface{}{}
}

// SetPermissionMode implements ToolWithPermissionMode.
// Pi has no permission gate, so this is stored but has no effect on
// BuildCommand or GetSandboxSettings.
func (p *PiTool) SetPermissionMode(mode string) {
	p.permissionMode = mode
}

// SetAutoContextPath implements ToolWithAutoContextPath.
// Stores the absolute path to the sandbox context file so it can be
// referenced in pi's settings or command line.
// The path must be absolute; relative paths are rejected.
func (p *PiTool) SetAutoContextPath(path string) {
	if !filepath.IsAbs(path) {
		return // reject relative paths silently; callers always provide absolute paths
	}
	p.contextFilePath = path
}

// EssentialConfigFiles implements ToolWithConfigDirFiles.
func (p *PiTool) EssentialConfigFiles() []string {
	return mustBundle("pi").Files
}

// SandboxSettingsFileName implements ToolWithConfigDirFiles.
func (p *PiTool) SandboxSettingsFileName() string { return mustBundle("pi").SandboxSettingsFile }

// StateConfigFileName implements ToolWithConfigDirFiles.
// Pi has no sibling state file.
func (p *PiTool) StateConfigFileName() string { return mustBundle("pi").StateFile }

// AlwaysSetupConfig implements ToolWithConfigDirFiles.
// Pi needs config dir setup even without host config dir so that
// settings.json exists for sandbox context injection.
func (p *PiTool) AlwaysSetupConfig() bool { return mustBundle("pi").AlwaysSetup }

// GetContainerEnv implements ToolWithContainerEnv.
// Redirects pi's session storage directory to the workspace mount so
// session data persists across ephemeral container recreations.
// Without this, sessions live in ~/.pi/agent/sessions/ (inside the container)
// and are destroyed when the ephemeral container is deleted.
func (p *PiTool) GetContainerEnv(workspacePath string) map[string]string {
	return map[string]string{
		"PI_CODING_AGENT_SESSION_DIR": filepath.Join(workspacePath, ".pi-sessions"),
	}
}
