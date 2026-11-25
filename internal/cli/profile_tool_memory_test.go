package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func TestPrintProfileTool_ShowsMemory(t *testing.T) {
	p := &config.ProfileConfig{Tool: &config.ToolConfig{Memory: config.ToolMemoryFresh}}
	out := captureOutput(t, &os.Stdout, func() { printProfileTool(p) })
	if !strings.Contains(out, "memory = \"fresh\"\n") {
		t.Errorf("profile show should print the memory setting, got:\n%s", out)
	}
}
