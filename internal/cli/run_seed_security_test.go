package cli

import (
	"testing"

	"github.com/coipond/coi/internal/config"
)

// The headless run's context learns about passwordless_sudo = false.
func TestSeedSecurityOptions_DisableSudo(t *testing.T) {
	no := false
	cfg := config.GetDefaultConfig()
	cfg.Security.PasswordlessSudo = &no
	if !(&App{cfg: cfg}).seedSecurityOptions().DisableSudo {
		t.Error("passwordless_sudo = false must reach the run's context")
	}
	if (&App{cfg: config.GetDefaultConfig()}).seedSecurityOptions().DisableSudo {
		t.Error("sudo on by default")
	}
}

// passwordless_sudo = false turns Docker off for the container too.
func TestHardeningPolicy_NoSudo(t *testing.T) {
	no := false
	cfg := config.GetDefaultConfig()
	cfg.Security.PasswordlessSudo = &no
	if (&App{cfg: cfg}).hardeningPolicy().DockerEnabled() {
		t.Error("no sudo must mean no Docker")
	}
}
