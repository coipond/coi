package cli

import (
	"io"
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

	old := os.Stderr
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wp
	defer func() { os.Stderr = old }()

	cfg := &config.Config{}
	cfg.Tool.Name = "claude"
	cfg.Tool.PermissionMode = mode
	for range 2 {
		if _, err := getConfiguredTool(cfg); err != nil {
			t.Fatal(err)
		}
	}

	_ = wp.Close()
	os.Stderr = old
	data, _ := io.ReadAll(rp)
	return string(data)
}

// A config file is not schema-checked, so an unknown value (a typo, the wrong
// case) runs as bypass; coi says so once instead of dropping the prompts the
// user asked for silently.
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
