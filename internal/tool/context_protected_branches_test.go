package tool

import (
	"encoding/json"
	"strings"
	"testing"
)

// The generated agent context must announce the branch guard when it is active,
// so the agent knows from startup to work on a feature branch.
func TestRenderContext_ProtectedBranches(t *testing.T) {
	base := ContextInfo{
		ContainerName: "coi-abc",
		ToolName:      "claude",
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
	}

	t.Run("markdown includes the section when set", func(t *testing.T) {
		info := base
		info.ProtectedBranches = []string{"main", "master"}
		md := RenderContextFileContent(info)
		if !strings.Contains(md, "## Protected Branches") {
			t.Fatalf("context markdown missing the Protected Branches section:\n%s", md)
		}
		if !strings.Contains(md, "main, master") {
			t.Errorf("section should name the protected branches:\n%s", md)
		}
	})

	t.Run("markdown omits the section when empty", func(t *testing.T) {
		md := RenderContextFileContent(base) // no ProtectedBranches
		if strings.Contains(md, "## Protected Branches") {
			t.Errorf("guard-off context must not advertise a Protected Branches section:\n%s", md)
		}
	})

	t.Run("json carries the field", func(t *testing.T) {
		info := base
		info.ProtectedBranches = []string{"main"}
		out, err := RenderContextFileJSON(info)
		if err != nil {
			t.Fatalf("RenderContextFileJSON: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("json: %v", err)
		}
		pb, ok := doc["protected_branches"].([]any)
		if !ok || len(pb) != 1 || pb[0] != "main" {
			t.Errorf("protected_branches not in JSON context: %v", doc["protected_branches"])
		}
	})
}
