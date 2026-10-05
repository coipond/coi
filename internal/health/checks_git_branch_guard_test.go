package health

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func TestCheckGitBranchGuard(t *testing.T) {
	t.Run("default is on and OK", func(t *testing.T) {
		hc := CheckGitBranchGuard(config.GetDefaultConfig())
		if hc.Status != StatusOK {
			t.Errorf("default guard should be OK, got %s", hc.Status)
		}
		if !strings.Contains(hc.Message, "main") || !strings.Contains(hc.Message, "master") {
			t.Errorf("message should name the protected branches: %q", hc.Message)
		}
	})

	t.Run("explicit empty disables → OK (informational, not a warning)", func(t *testing.T) {
		cfg := config.GetDefaultConfig()
		empty := []string{}
		cfg.Git.ProtectedBranches = &empty
		hc := CheckGitBranchGuard(cfg)
		// An explicit opt-out is a valid choice, reported as OK — not flagged as a
		// problem to remediate.
		if hc.Status != StatusOK {
			t.Errorf("intentionally-disabled guard should be OK, got %s", hc.Status)
		}
		if !strings.Contains(hc.Message, "Disabled") {
			t.Errorf("message should still note the guard is disabled: %q", hc.Message)
		}
	})

	t.Run("nil config does not panic", func(t *testing.T) {
		hc := CheckGitBranchGuard(nil)
		// nil cfg is an edge path — the check must be defensive and never panic.
		if hc.Name != "git_branch_guard" {
			t.Errorf("unexpected name %q", hc.Name)
		}
	})
}
