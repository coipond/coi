package cli

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/tool"
)

// getConfiguredTool applies [tool] binary, so both launch paths — coi shell's
// command string and the coi run --prompt / tool spec argv — start it.
func TestGetConfiguredTool_AppliesBinary(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "")
	cfg := &config.Config{}
	cfg.Tool.Name = "claude"
	cfg.Tool.Binary = "/workspace/fake-agent.sh"

	tl, err := getConfiguredTool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cmd := buildCLICommand("sid", false, false, t.TempDir(), "", tl); !strings.HasPrefix(cmd, "/workspace/fake-agent.sh --verbose") {
		t.Errorf("coi shell command = %q, want it to start with the configured binary", cmd)
	}
	argv, _, err := buildToolLaunchArgv(tl, tool.LaunchSpec{SessionID: "sid"})
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "/workspace/fake-agent.sh" {
		t.Errorf("launch argv[0] = %q, want the configured binary", argv[0])
	}
}

// An unsafe value fails loudly instead of being dropped silently.
func TestGetConfiguredTool_RejectsUnsafeBinary(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tool.Name = "claude"
	cfg.Tool.Binary = "claude update; claude"
	if _, err := getConfiguredTool(cfg); err == nil || !strings.Contains(err.Error(), "[tool] binary") {
		t.Errorf("want a [tool] binary validation error, got %v", err)
	}
}

// The COI_USE_DUMMY test switch keeps the final say over argv[0].
func TestBuildCLICommand_DummyOverridesBinary(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "1")
	cfg := &config.Config{}
	cfg.Tool.Name = "claude"
	cfg.Tool.Binary = "/workspace/fake-agent.sh"
	tl, err := getConfiguredTool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cmd := buildCLICommand("sid", false, false, t.TempDir(), "", tl); !strings.HasPrefix(cmd, "dummy ") {
		t.Errorf("command = %q, want the dummy stub", cmd)
	}
}
