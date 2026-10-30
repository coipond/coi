package tool

import "path/filepath"

// Opencode2Tool implements Tool for OpenCode v2, installed next to v1 as
// "opencode2". It launches like opencode (same --continue/--session/run
// flags) and reuses its config bundle and container env; only the name,
// binary, sessions dir, session lookup (opencode2 has none, so a resume uses
// --continue) and data dirs (its own, plus a plan dir) differ.
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
