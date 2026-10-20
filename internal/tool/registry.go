package tool

import (
	"fmt"
	"sort"
	"strings"
)

// registry maps tool names to their factory functions
var registry = map[string]func() Tool{
	"claude":    NewClaude,
	"opencode":  NewOpencode,
	"opencode2": NewOpencode2,
	"pi":        NewPi,
	"codex":     NewCodex,
	"omp":       NewOmp,
}

// Get returns a tool by name
func Get(name string) (Tool, error) {
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s (supported: %s)", name, strings.Join(ListSupported(), ", "))
	}
	return factory(), nil
}

// GetDefault returns the default tool (Claude)
func GetDefault() Tool {
	return NewClaude()
}

// DefaultBuildAgents returns the agents installed into the image when no
// explicit selection is made — it must stay in sync with build.sh's
// ${COI_AGENTS:-...} default (enforced by TestBuildScriptDispatchMatchesRegistry).
// codex and opencode2 are supported but opt-in only (issue #698), so they are
// not in this set.
func DefaultBuildAgents() []string {
	return []string{"claude", "opencode", "pi"}
}

// ListSupported returns a sorted list of supported tool names
func ListSupported() []string {
	tools := make([]string, 0, len(registry))
	for name := range registry {
		tools = append(tools, name)
	}
	sort.Strings(tools)
	return tools
}
