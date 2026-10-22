package tool

// Opencode2Tool implements Tool for OpenCode v2, installed next to v1 as
// "opencode2". It launches like opencode (same --continue/--session/run
// flags) and reuses its config bundle and container env; only the name,
// binary and sessions dir differ.
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
