package tool

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// gooseSessionID matches goose's session IDs (<yyyymmdd>_<n>). It also keeps
// a discovered ID shell-safe for the launch command.
var gooseSessionID = regexp.MustCompile(`^[0-9]{8}_[0-9]+$`)

// GooseTool implements Tool for goose (https://goose-docs.ai)
type GooseTool struct {
	permissionMode string
	binary         string // [tool] binary override; empty means "goose"
	workspacePath  string // set by SessionDiscoveryCommand
	discoveredID   string // set by SetSessionDiscoveryOutput
}

// NewGoose creates a new goose tool instance
func NewGoose() Tool { return &GooseTool{} }

// Name returns "goose".
func (g *GooseTool) Name() string { return "goose" }

// Binary returns the executable to launch: the [tool] binary override if set,
// else "goose".
func (g *GooseTool) Binary() string {
	if g.binary != "" {
		return g.binary
	}
	return "goose"
}

// SetBinary implements ToolWithBinary: the executable to launch instead of
// "goose" ([tool] binary). An empty or unsafe value leaves the default.
func (g *GooseTool) SetBinary(path string) {
	if path != "" && ValidateBinary(path) == nil {
		g.binary = path
	}
}

// ConfigDirName returns the config directory for goose (~/.config/goose).
func (g *GooseTool) ConfigDirName() string { return mustBundle("goose").ConfigDir }

// SessionsDirName returns "sessions-goose".
func (g *GooseTool) SessionsDirName() string { return "sessions-goose" }

// BuildCommand builds the goose launch command. It always uses the `session`
// subcommand: bare `goose` with no config file runs first-time setup, whose
// telemetry dialog ignores GOOSE_TELEMETRY_OFF. A resume needs a session ID:
// bare `--resume` takes goose's newest session in any directory, so without
// one a new session starts.
func (g *GooseTool) BuildCommand(sessionID string, resume bool, resumeSessionID string) []string {
	cmd := []string{g.Binary(), "session"}
	if resume && resumeSessionID != "" {
		cmd = append(cmd, "--resume", "--session-id", resumeSessionID)
	}
	return cmd
}

// DiscoverSessionID returns the session found by the in-container session
// list (SetSessionDiscoveryOutput), or "". goose keeps its sessions in a
// SQLite store in its data dir, not in stateDir.
func (g *GooseTool) DiscoverSessionID(stateDir string) string { return g.discoveredID }

// SessionDiscoveryCommand implements ToolWithContainerSessionDiscovery: it
// lists the sessions goose matches to the workspace, newest activity first.
func (g *GooseTool) SessionDiscoveryCommand(workspacePath string) []string {
	g.workspacePath = workspacePath
	return []string{g.Binary(), "session", "list", "--format", "json", "--working_dir", workspacePath}
}

// SetSessionDiscoveryOutput implements ToolWithContainerSessionDiscovery. It
// takes the first listed session whose working_dir is the workspace itself:
// goose's --working_dir filter also matches other dirs (a subdir). Anything
// else (no such row, a log line, an ID of unexpected shape) leaves no session.
func (g *GooseTool) SetSessionDiscoveryOutput(output string) {
	g.discoveredID = ""
	var rows []struct {
		ID         string `json:"id"`
		WorkingDir string `json:"working_dir"`
	}
	start := strings.Index(output, "[")
	if start < 0 || g.workspacePath == "" || json.Unmarshal([]byte(output[start:]), &rows) != nil {
		return
	}
	want := filepath.Clean(g.workspacePath)
	for _, r := range rows {
		if r.WorkingDir != "" && filepath.Clean(r.WorkingDir) == want {
			if gooseSessionID.MatchString(r.ID) {
				g.discoveredID = r.ID
			}
			return
		}
	}
}

// GetSandboxSettings returns an empty map: goose's config is YAML and coi
// merges only JSON settings. The image's /etc/goose/config.yaml holds the
// sandbox defaults instead.
func (g *GooseTool) GetSandboxSettings() map[string]interface{} {
	return map[string]interface{}{}
}

// SetPermissionMode implements ToolWithPermissionMode. The mode is stored but
// currently has no effect on BuildCommand or GetSandboxSettings.
func (g *GooseTool) SetPermissionMode(mode string) {
	g.permissionMode = mode
}

// EssentialConfigFiles implements ToolWithConfigDirFiles, returning the files
// listed in goose's credential bundle.
func (g *GooseTool) EssentialConfigFiles() []string {
	return mustBundle("goose").Files
}

// SandboxSettingsFileName implements ToolWithConfigDirFiles.
func (g *GooseTool) SandboxSettingsFileName() string {
	return mustBundle("goose").SandboxSettingsFile
}

// StateConfigFileName implements ToolWithConfigDirFiles.
func (g *GooseTool) StateConfigFileName() string { return mustBundle("goose").StateFile }

// AlwaysSetupConfig implements ToolWithConfigDirFiles.
func (g *GooseTool) AlwaysSetupConfig() bool { return mustBundle("goose").AlwaysSetup }

// DataDirs implements ToolWithDataDirs. goose keeps its SQLite session
// database (with its WAL files) in the XDG data dir and its logs in the XDG
// state dir; host mounts keep the database consistent when an ephemeral
// container goes away.
func (g *GooseTool) DataDirs() []DataDir {
	return []DataDir{
		{Name: "share", HomeRelPath: filepath.Join(".local", "share", "goose")},
		{Name: "state", HomeRelPath: filepath.Join(".local", "state", "goose")},
	}
}

// SessionExcludedFiles implements ToolWithSessionExcludes: the TLS and
// roaming private keys of `goose serve`, which coi does not run.
func (g *GooseTool) SessionExcludedFiles() []string {
	return []string{"tls", "roaming_node_key"}
}
