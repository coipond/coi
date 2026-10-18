package tool

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// opencodeSessionID matches opencode's session IDs ("ses_" + base62). It also
// keeps a discovered ID shell-safe for the launch command.
var opencodeSessionID = regexp.MustCompile(`^ses_[A-Za-z0-9]+$`)

// OpencodeTool implements Tool for opencode (https://opencode.ai)
type OpencodeTool struct {
	permissionMode  string // "bypass" (default) or "interactive"
	contextFilePath string // absolute path to sandbox context file inside container (set by SetAutoContextPath)
	binary          string // [tool] binary override; empty means "opencode"
	discoveredID    string // set by SetSessionDiscoveryOutput
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
// When resume is true, passes --session <id> if a session ID is known (see
// DiscoverSessionID), else --continue to resume opencode's last session.
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

// DiscoverSessionID returns the session found by the in-container DB query
// (SetSessionDiscoveryOutput), or "" so BuildCommand falls back to --continue.
// opencode keeps sessions in SQLite in the workspace, not in stateDir.
func (c *OpencodeTool) DiscoverSessionID(stateDir string) string { return c.discoveredID }

// SessionDiscoveryCommand implements ToolWithContainerSessionDiscovery: it
// queries opencode's own DB (`opencode db` resolves the channel-specific DB
// file) for the latest root, unarchived session of the workspace.
func (c *OpencodeTool) SessionDiscoveryCommand(workspacePath string) []string {
	query := "SELECT id FROM session WHERE parent_id IS NULL AND time_archived IS NULL" +
		" AND directory = '" + strings.ReplaceAll(workspacePath, "'", "''") + "'" +
		" ORDER BY time_updated DESC LIMIT 1"
	return []string{c.Binary(), "db", query, "--format", "json"}
}

// SetSessionDiscoveryOutput implements ToolWithContainerSessionDiscovery. It
// parses the JSON rows printed by SessionDiscoveryCommand; anything else
// (no rows, a log line, an ID of unexpected shape) leaves no session.
func (c *OpencodeTool) SetSessionDiscoveryOutput(output string) {
	c.discoveredID = ""
	var rows []struct {
		ID string `json:"id"`
	}
	if start := strings.Index(output, "["); start >= 0 {
		if json.Unmarshal([]byte(output[start:]), &rows) == nil && len(rows) > 0 && opencodeSessionID.MatchString(rows[0].ID) {
			c.discoveredID = rows[0].ID
		}
	}
}

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

// GetContainerEnv implements ToolWithContainerEnv.
// Redirects XDG data and state directories to the workspace mount so opencode's
// SQLite database persists across ephemeral container recreations.
// Without this, data lives in ~/.local/share/opencode/ (inside the container)
// and is destroyed when the ephemeral container is deleted.
func (c *OpencodeTool) GetContainerEnv(workspacePath string) map[string]string {
	return map[string]string{
		"XDG_DATA_HOME":  filepath.Join(workspacePath, ".local", "share"),
		"XDG_STATE_HOME": filepath.Join(workspacePath, ".local", "state"),
	}
}
