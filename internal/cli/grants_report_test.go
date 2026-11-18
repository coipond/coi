package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/session"
)

// The text report is Render's block; --json prints the same grants as one
// JSON line instead.
func TestGrantsReport(t *testing.T) {
	g := &session.Grants{
		Workspace: session.MountGrant{HostPath: "/p", ContainerPath: "/workspace"},
		Env:       session.EnvGrants{FromHost: []string{"GH_TOKEN"}},
	}
	text, err := grantsReport(g, false)
	if err != nil || text != g.Render() {
		t.Errorf("text report = %q, %v; want Render's", text, err)
	}
	out, err := grantsReport(g, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "}\n") {
		t.Errorf("JSON report should be one line: %q", out)
	}
	var got struct {
		Workspace struct {
			HostPath string `json:"host_path"`
		}
		Env struct {
			FromHost []string `json:"from_host"`
		}
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", out, err)
	}
	if got.Workspace.HostPath != "/p" || len(got.Env.FromHost) != 1 || got.Env.FromHost[0] != "GH_TOKEN" {
		t.Errorf("JSON report = %s", out)
	}
	if shellCmd.Flags().Lookup("json") == nil {
		t.Error("coi shell has no --json flag")
	}
}
