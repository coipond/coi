package cli

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// toolStderr returns what getConfiguredTool writes to os.Stderr for a
// [tool] permission_mode, called twice as some commands do.
func toolStderr(t *testing.T, mode config.PermissionMode) string {
	t.Helper()
	permissionModeWarning = sync.Once{}
	t.Cleanup(func() { permissionModeWarning = sync.Once{} })

	cfg := &config.Config{}
	cfg.Tool.Name = "claude"
	cfg.Tool.PermissionMode = mode
	return captureOutput(t, &os.Stderr, func() {
		for range 2 {
			if _, err := getConfiguredTool(cfg); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestGetConfiguredTool_WarnsOnUnknownPermissionMode(t *testing.T) {
	stderr := toolStderr(t, "Interactive")
	if got := strings.Count(stderr, "permission_mode"); got != 1 {
		t.Fatalf("got %d permission_mode warnings, want 1; stderr: %q", got, stderr)
	}
	for _, want := range []string{`"Interactive"`, `"bypass", "interactive"`, `using "bypass"`} {
		if !strings.Contains(stderr, want) {
			t.Errorf("warning lacks %s: %q", want, stderr)
		}
	}
}

func TestGetConfiguredTool_NoWarningForKnownPermissionMode(t *testing.T) {
	for _, mode := range []config.PermissionMode{"", "bypass", "interactive"} {
		if stderr := toolStderr(t, mode); stderr != "" {
			t.Errorf("permission_mode = %q: unexpected stderr %q", mode, stderr)
		}
	}
}
