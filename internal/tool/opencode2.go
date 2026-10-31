package tool

import "path/filepath"

// Opencode2Tool implements Tool for OpenCode v2, installed next to v1 as
// "opencode2". It launches like opencode (same --continue/--session/run
// flags, plus --standalone) and reuses its config dir and container env;
// only the name, binary, launch flags, sessions dir, session lookup
// (opencode2 has none, so a resume uses --continue), data dirs (its own, plus
// a plan dir), config files and files kept out of a saved session differ.
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

// BuildCommand builds the opencode2 launch command: opencode's, plus the v2
// flags (see v2Flags).
func (c *Opencode2Tool) BuildCommand(sessionID string, resume bool, resumeSessionID string) []string {
	return insertFlags(c.OpencodeTool.BuildCommand(sessionID, resume, resumeSessionID), 1, c.v2Flags())
}

// BuildHeadlessCommand implements ToolWithHeadlessPrompt: opencode's
// `run` command, plus the v2 flags (see v2Flags) after `run`: v2 before
// 2.2.0 (2.1.0 is build.sh's fallback) rejects --standalone before the
// subcommand.
func (c *Opencode2Tool) BuildHeadlessCommand(spec LaunchSpec) ([]string, error) {
	cmd, err := c.OpencodeTool.BuildHeadlessCommand(spec)
	if err != nil {
		return nil, err
	}
	return insertFlags(cmd, 2, c.v2Flags()), nil
}

// v2Flags returns the flags opencode2 adds to opencode's command.
// --standalone: without it the v2 TUI is a client of a detached
// `opencode serve --service` that outlives it, keeps the DB open and writes
// service.json (with its password); --standalone runs a private server that
// exits with the TUI.
// --auto (bypass mode only): v2 applies the V1 `permission` rules of
// opencode.json before any V2 `permissions` rule, from the host or the
// workspace, so a V2 `ask` rule would beat coi's bypass. --auto approves all
// that is not explicitly denied. The V2 rule cannot go in opencode.json:
// OpenCode v1 reads the same file and rejects the `permissions` key.
func (c *Opencode2Tool) v2Flags() []string {
	if c.permissionMode == "interactive" {
		return []string{"--standalone"}
	}
	return []string{"--standalone", "--auto"}
}

// insertFlags inserts flags into cmd at index at.
func insertFlags(cmd []string, at int, flags []string) []string {
	return append(append(append([]string{}, cmd[:at]...), flags...), cmd[at:]...)
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
