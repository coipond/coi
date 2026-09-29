package cli

import (
	"testing"

	"github.com/mensfeld/coi/internal/tool"
)

// TestBuildCLICommand_Opencode_NewSession verifies that opencode gets a bare
// command when starting a new session (no resume flags).
func TestBuildCLICommand_Opencode_NewSession(t *testing.T) {
	oc := tool.NewOpencode()
	cmd := buildCLICommand("session-1", false, false, "/tmp/sessions", "", oc)
	if cmd != "opencode" {
		t.Errorf("buildCLICommand(new session) = %q, want %q", cmd, "opencode")
	}
}

// TestBuildCLICommand_Opencode_Resume verifies that opencode gets --continue
// when resuming without a specific session ID.
func TestBuildCLICommand_Opencode_Resume(t *testing.T) {
	oc := tool.NewOpencode()
	cmd := buildCLICommand("", true, false, "/tmp/sessions", "prev-session", oc)
	if cmd != "opencode --continue" {
		t.Errorf("buildCLICommand(resume) = %q, want %q", cmd, "opencode --continue")
	}
}

// TestBuildCLICommand_Opencode_RestoreOnly verifies that opencode gets --continue
// when restoring from saved state (ephemeral container recreation).
func TestBuildCLICommand_Opencode_RestoreOnly(t *testing.T) {
	oc := tool.NewOpencode()
	cmd := buildCLICommand("", false, true, "/tmp/sessions", "prev-session", oc)
	if cmd != "opencode --continue" {
		t.Errorf("buildCLICommand(restoreOnly) = %q, want %q", cmd, "opencode --continue")
	}
}

// TestBuildCLICommand_Opencode_DummyMode verifies that the dummy mode override
// replaces "opencode" with "dummy" (used in CI/testing).
func TestBuildCLICommand_Opencode_DummyMode(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "1")

	oc := tool.NewOpencode()
	cmd := buildCLICommand("session-1", false, false, "/tmp/sessions", "", oc)
	if cmd != "dummy" {
		t.Errorf("buildCLICommand(dummy) = %q, want %q", cmd, "dummy")
	}
}

// TestBuildCLICommand_Opencode_DummyModeResume verifies dummy override preserves
// resume flags.
func TestBuildCLICommand_Opencode_DummyModeResume(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "1")

	oc := tool.NewOpencode()
	cmd := buildCLICommand("", true, false, "/tmp/sessions", "prev-session", oc)
	if cmd != "dummy --continue" {
		t.Errorf("buildCLICommand(dummy resume) = %q, want %q", cmd, "dummy --continue")
	}
}

// TestMergeToolEnv_Opencode verifies that opencode's XDG env vars are merged
// into the container environment.
func TestMergeToolEnv_Opencode(t *testing.T) {
	env := map[string]string{"HOME": "/home/code"}
	oc := tool.NewOpencode()
	mergeToolEnv(env, oc, "/workspace")

	if env["XDG_DATA_HOME"] != "/workspace/.local/share" {
		t.Errorf("XDG_DATA_HOME = %q, want %q", env["XDG_DATA_HOME"], "/workspace/.local/share")
	}
	if env["XDG_STATE_HOME"] != "/workspace/.local/state" {
		t.Errorf("XDG_STATE_HOME = %q, want %q", env["XDG_STATE_HOME"], "/workspace/.local/state")
	}
	// HOME should not be overwritten
	if env["HOME"] != "/home/code" {
		t.Errorf("HOME = %q, want %q", env["HOME"], "/home/code")
	}
}

// TestMergeToolEnv_Claude verifies that Claude (no ToolWithContainerEnv) doesn't
// add extra env vars.
func TestMergeToolEnv_Claude(t *testing.T) {
	env := map[string]string{"HOME": "/home/code"}
	cl := tool.NewClaude()
	mergeToolEnv(env, cl, "/workspace")

	if _, ok := env["XDG_DATA_HOME"]; ok {
		t.Error("Claude should not set XDG_DATA_HOME")
	}
}
