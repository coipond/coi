package tool

import "path/filepath"

// Opencode2Tool implements Tool for OpenCode v2, installed next to v1 as
// "opencode2". It launches like opencode (same --continue/--session/run
// flags, plus --standalone) and reuses its config dir and container env;
// only the name, binary, launch flags, sessions dir, session lookup
// (opencode2 has none, so a resume uses --continue), data dirs (its own, plus
// a plan dir), config files, sandbox settings and files kept out of a saved
// session differ.
type Opencode2Tool struct {
	OpencodeTool
}

// NewOpencode2 creates a new opencode2 tool instance
func NewOpencode2() Tool {
	return &Opencode2Tool{OpencodeTool{binary: "opencode2"}}
}

// Name returns "opencode2".
func (c *Opencode2Tool) Name() string { return "opencode2" }

// SessionsDirName returns "sessions-opencode2".
func (c *Opencode2Tool) SessionsDirName() string { return "sessions-opencode2" }

// BuildCommand builds the opencode2 launch command: opencode's, plus
// --standalone. Without it the v2 TUI is a client of a detached
// `opencode serve --service` that outlives it, keeps the DB open and writes
// service.json (with its password); --standalone runs a private server that
// exits with the TUI.
func (c *Opencode2Tool) BuildCommand(sessionID string, resume bool, resumeSessionID string) []string {
	return standalone(c.OpencodeTool.BuildCommand(sessionID, resume, resumeSessionID), 1)
}

// BuildHeadlessCommand implements ToolWithHeadlessPrompt: opencode's
// `run` command, plus --standalone (see BuildCommand) after `run`: v2 before
// 2.2.0 (2.1.0 is build.sh's fallback) rejects it before the subcommand.
func (c *Opencode2Tool) BuildHeadlessCommand(spec LaunchSpec) ([]string, error) {
	cmd, err := c.OpencodeTool.BuildHeadlessCommand(spec)
	if err != nil {
		return nil, err
	}
	return standalone(cmd, 2), nil
}

// standalone inserts --standalone into cmd at index at.
func standalone(cmd []string, at int) []string {
	return append(append(append([]string{}, cmd[:at]...), "--standalone"), cmd[at:]...)
}

// SessionExcludedFiles implements ToolWithSessionExcludes. service.json holds
// the v2 background service's URL, PID and password; a saved session must not
// keep it, even if opencode2 was started by hand without --standalone.
func (c *Opencode2Tool) SessionExcludedFiles() []string { return []string{"service.json"} }

// SessionDiscoveryCommand returns nil: OpenCode v2 keeps sessions in
// session_v2, which the inherited v1 query does not read, so opencode2 resumes
// with --continue.
func (c *Opencode2Tool) SessionDiscoveryCommand(string) []string { return nil }

// DataDirs implements ToolWithDataDirs. opencode2 uses opencode's container
// paths, backed by its own host dirs, so OpenCode v1 never opens a v2 DB. They
// are not taken from the workspace: data older coi kept there is v1's. Plus
// ~/.opencode/plan, where v2's Plan agent writes its plan files (v1 wrote them
// to <workspace>/.opencode/plans, which the workspace already keeps).
func (c *Opencode2Tool) DataDirs() []DataDir {
	return []DataDir{
		{Name: "share", HomeRelPath: filepath.Join(".local", "share", "opencode")},
		{Name: "state", HomeRelPath: filepath.Join(".local", "state", "opencode")},
		{Name: "plan", HomeRelPath: filepath.Join(".opencode", "plan"), FromContainer: true},
	}
}

// GetSandboxSettings returns opencode's settings plus a V2 `permissions`
// rule with the same effect. v2 applies V1 `permission` rules before V2
// `permissions` rules and the last matching rule wins, so a host V2 rule would
// beat the V1 one. The merge replaces the host's `permissions` list, which
// keeps coi's rule the last config rule.
func (c *Opencode2Tool) GetSandboxSettings() map[string]interface{} {
	settings := c.OpencodeTool.GetSandboxSettings()
	effect := "allow"
	if c.permissionMode == "interactive" {
		effect = "ask"
	}
	settings["permissions"] = []map[string]string{
		{"action": "*", "resource": "*", "effect": effect},
	}
	return settings
}

// ConfigDirName returns opencode2's config dir, shared with opencode.
func (c *Opencode2Tool) ConfigDirName() string { return mustBundle("opencode2").ConfigDir }

// EssentialConfigFiles implements ToolWithConfigDirFiles.
func (c *Opencode2Tool) EssentialConfigFiles() []string {
	return mustBundle("opencode2").Files
}

// SandboxSettingsFileName implements ToolWithConfigDirFiles.
func (c *Opencode2Tool) SandboxSettingsFileName() string {
	return mustBundle("opencode2").SandboxSettingsFile
}

// StateConfigFileName implements ToolWithConfigDirFiles.
func (c *Opencode2Tool) StateConfigFileName() string { return mustBundle("opencode2").StateFile }

// AlwaysSetupConfig implements ToolWithConfigDirFiles.
func (c *Opencode2Tool) AlwaysSetupConfig() bool { return mustBundle("opencode2").AlwaysSetup }
