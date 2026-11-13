package tool

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The agent-installers workflow builds an image with each agent alone. A new
// tool registered here must be added to its matrix, or its installer drifts
// unchecked (#1035).
func TestAgentInstallersWorkflowCoversEveryTool(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/agent-installers.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s+agent: \[([^\]]*)\]`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no `agent: [...]` matrix in agent-installers.yml")
	}
	var agents []string
	for _, a := range strings.Split(string(m[1]), ",") {
		agents = append(agents, strings.TrimSpace(a))
	}
	slices.Sort(agents)
	if want := ListSupported(); !slices.Equal(agents, want) {
		t.Errorf("agent-installers.yml matrix = %v, want every supported tool %v", agents, want)
	}
}
