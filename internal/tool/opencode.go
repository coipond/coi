package tool

import (
	"fmt"
	"path/filepath"
)

// OpencodeTool implements Tool for opencode (https://opencode.ai)
type OpencodeTool struct {
	permissionMode  string // "bypass" (default) or "interactive"
	contextFilePath string // absolute path to sandbox context file inside container (set by SetAutoContextPath)
	binary          string // [tool] binary override; empty means "opencode"
}

// NewOpencode creates a new opencode tool instance
func NewOpencode() Tool { return &OpencodeTool{} }

// Name returns "opencode".
func (c *OpencodeTool) Name() string { return "opencode" }

// Binary returns the executable to launch: the [tool] binary override if set,
// else "opencode".
func (c *OpencodeTool) Binary() string {
	if c.binary != "" {
		return c.binary
	}
	return "opencode"
}

// SetBinary implements ToolWithBinary: the executable to launch instead of
// "opencode" ([tool] binary). An empty or unsafe value leaves the default.
func (c *OpencodeTool) SetBinary(path string) {
	if path != "" && ValidateBinary(path) == nil {
		c.binary = path
	}
}

// ConfigDirName returns the XDG-standard config directory for opencode.
func (c *OpencodeTool) ConfigDirName() string { return mustBundle("opencode").ConfigDir }

// SessionsDirName returns "sessions-opencode".
func (c *OpencodeTool) SessionsDirName() string { return "sessions-opencode" }

// BuildCommand builds the opencode launch command.
// When resume is true, passes --continue to auto-resume the last session,
// or --session <id> if a specific session ID is provided.
func (c *OpencodeTool) BuildCommand(sessionID string, resume bool, resumeSessionID string) []string {
	cmd := []string{c.Binary()}
	if resume {
		if resumeSessionID != "" {
			cmd = append(cmd, "--session", resumeSessionID)
		} else {
			cmd = append(cmd, "--continue")
		}
	}
	return cmd
}

// BuildHeadlessCommand implements ToolWithHeadlessPrompt. `opencode run`
// runs to completion and exits with a status code; it takes the same
// --session/--continue resume flags as the TUI and works in OpenCode v1 and
// v2. The prompt goes in on stdin (`< <file>`), which both versions read as
// the message when no positional is given: a positional prompt starting with
// "-" is parsed as flags, and v2 repeats any args after "--". Stdin is always
// redirected, so an open stdin inherited from the caller can't block the run.
// It has no system-prompt flag, so a SystemPromptFile is rejected.
func (c *OpencodeTool) BuildHeadlessCommand(spec LaunchSpec) ([]string, error) {
	if spec.SystemPromptFile != "" {
		return nil, fmt.Errorf("opencode run has no system-prompt flag")
	}
	base := c.BuildCommand(spec.SessionID, spec.Resume, spec.ResumeSessionID)
	cmd := append([]string{base[0], "run"}, base[1:]...)
	stdin := "/dev/null"
	if spec.PromptFile != "" {
		stdin = spec.PromptFile
	}
	return append(cmd, "<"+stdin), nil
}

// DiscoverSessionID returns "" because opencode uses SQLite (not JSONL files).
func (c *OpencodeTool) DiscoverSessionID(stateDir string) string { return "" }

// GetSandboxSettings returns the opencode permission config.
// In bypass mode (default): injects {"permission": {"*": "allow"}} so opencode runs
// without interactive prompts.
// In interactive mode: injects {"permission": {"*": "ask"}} so opencode prompts the
// user before each action (human-in-the-loop).
func (c *OpencodeTool) GetSandboxSettings() map[string]interface{} {
	var settings map[string]interface{}
	if c.permissionMode == "interactive" {
		settings = map[string]interface{}{
			"permission": map[string]interface{}{
				"*": "ask",
			},
		}
	} else {
		settings = map[string]interface{}{
			"permission": map[string]interface{}{
				"*": "allow",
			},
		}
	}

	// Include instructions field referencing the sandbox context file
	if c.contextFilePath != "" {
		settings["instructions"] = []string{c.contextFilePath}
	}

	return settings
}

// SetPermissionMode sets the permission mode for opencode.
// Valid values: "bypass" (default) or "interactive" (human-in-the-loop).
func (c *OpencodeTool) SetPermissionMode(mode string) {
	c.permissionMode = mode
}

// SetAutoContextPath implements ToolWithAutoContextPath.
// Stores the absolute path to the sandbox context file so it can be
// referenced in the opencode.json instructions field.
func (c *OpencodeTool) SetAutoContextPath(path string) {
	c.contextFilePath = path
}

// EssentialConfigFiles implements ToolWithConfigDirFiles.
func (c *OpencodeTool) EssentialConfigFiles() []string {
	return mustBundle("opencode").Files
}

// SandboxSettingsFileName implements ToolWithConfigDirFiles.
func (c *OpencodeTool) SandboxSettingsFileName() string {
	return mustBundle("opencode").SandboxSettingsFile
}

// StateConfigFileName implements ToolWithConfigDirFiles.
// Opencode has no sibling state file.
func (c *OpencodeTool) StateConfigFileName() string { return mustBundle("opencode").StateFile }

// AlwaysSetupConfig implements ToolWithConfigDirFiles.
// Opencode needs sandbox permission bypass even without host config dir.
func (c *OpencodeTool) AlwaysSetupConfig() bool { return mustBundle("opencode").AlwaysSetup }

// GetContainerEnv implements ToolWithContainerEnv. Opencode needs no extra env:
// its data lives at the XDG defaults, which DataDirs backs with host mounts.
// It still returns an (empty) map so the container-env reconcile unsets the
// XDG_DATA_HOME/XDG_STATE_HOME that older coi versions pointed at the
// workspace on a reused persistent container.
func (c *OpencodeTool) GetContainerEnv(_ string) map[string]string {
	return map[string]string{}
}

// DataDirs implements ToolWithDataDirs. Opencode keeps its SQLite session
// database and its snapshot git repo in the XDG data dir, and prompt history
// and model picks in the XDG state dir. The snapshot repo tracks the whole
// workspace, so these must stay out of it: under /workspace each snapshot
// re-added the snapshot repo itself, growing it without bound (#929).
func (c *OpencodeTool) DataDirs() []DataDir {
	return []DataDir{
		{Name: "share", HomeRelPath: filepath.Join(".local", "share", "opencode")},
		{Name: "state", HomeRelPath: filepath.Join(".local", "state", "opencode")},
	}
}
