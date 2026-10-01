package cli

import (
	"testing"

	"github.com/coipond/coi/internal/tool"
)

// TestBuildCLICommand_Pi_NewSession verifies that pi gets a bare
// command when starting a new session (no resume flags).
func TestBuildCLICommand_Pi_NewSession(t *testing.T) {
	pi := tool.NewPi()
	cmd := buildCLICommand("session-1", false, false, "/tmp/sessions", "", pi)
	if cmd != "pi" {
		t.Errorf("buildCLICommand(new session) = %q, want %q", cmd, "pi")
	}
}

// TestBuildCLICommand_Pi_Resume verifies that pi gets --continue
// when resuming without a specific session ID.
func TestBuildCLICommand_Pi_Resume(t *testing.T) {
	pi := tool.NewPi()
	cmd := buildCLICommand("", true, false, "/tmp/sessions", "prev-session", pi)
	if cmd != "pi --continue" {
		t.Errorf("buildCLICommand(resume) = %q, want %q", cmd, "pi --continue")
	}
}

// TestBuildCLICommand_Pi_RestoreOnly verifies that pi gets --continue
// when restoring from saved state (ephemeral container recreation).
func TestBuildCLICommand_Pi_RestoreOnly(t *testing.T) {
	pi := tool.NewPi()
	cmd := buildCLICommand("", false, true, "/tmp/sessions", "prev-session", pi)
	if cmd != "pi --continue" {
		t.Errorf("buildCLICommand(restoreOnly) = %q, want %q", cmd, "pi --continue")
	}
}

// TestBuildCLICommand_Pi_DummyMode verifies that the dummy mode override
// replaces "pi" with "dummy" (used in CI/testing).
func TestBuildCLICommand_Pi_DummyMode(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "1")

	pi := tool.NewPi()
	cmd := buildCLICommand("session-1", false, false, "/tmp/sessions", "", pi)
	if cmd != "dummy" {
		t.Errorf("buildCLICommand(dummy) = %q, want %q", cmd, "dummy")
	}
}

// TestBuildCLICommand_Pi_DummyModeResume verifies dummy override preserves
// resume flags.
func TestBuildCLICommand_Pi_DummyModeResume(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "1")

	pi := tool.NewPi()
	cmd := buildCLICommand("", true, false, "/tmp/sessions", "prev-session", pi)
	if cmd != "dummy --continue" {
		t.Errorf("buildCLICommand(dummy resume) = %q, want %q", cmd, "dummy --continue")
	}
}

// TestMergeToolEnv_Pi verifies that pi's session dir env var is merged
// into the container environment.
func TestMergeToolEnv_Pi(t *testing.T) {
	env := map[string]string{"HOME": "/home/code"}
	pi := tool.NewPi()
	mergeToolEnv(env, pi, "/workspace")

	if env["PI_CODING_AGENT_SESSION_DIR"] != "/workspace/.pi-sessions" {
		t.Errorf("PI_CODING_AGENT_SESSION_DIR = %q, want %q", env["PI_CODING_AGENT_SESSION_DIR"], "/workspace/.pi-sessions")
	}
	// HOME should not be overwritten
	if env["HOME"] != "/home/code" {
		t.Errorf("HOME = %q, want %q", env["HOME"], "/home/code")
	}
}
