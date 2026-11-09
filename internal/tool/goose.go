package tool

// GooseTool implements Tool for goose (https://goose-docs.ai)
type GooseTool struct {
	permissionMode string
	binary         string // [tool] binary override; empty means "goose"
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
// telemetry dialog ignores GOOSE_TELEMETRY_OFF.
func (g *GooseTool) BuildCommand(sessionID string, resume bool, resumeSessionID string) []string {
	return []string{g.Binary(), "session"}
}

// DiscoverSessionID returns "": goose keeps its sessions in a SQLite store
// outside the config dir.
func (g *GooseTool) DiscoverSessionID(stateDir string) string { return "" }

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
