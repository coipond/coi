package cli

import (
	"os"
	"strings"
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

// An explicit docker = true under passwordless_sudo = false is named in the
// warning; kernel-surface hardening keeps its own name.
func TestWarnDockerHardeningConflict_NoSudo(t *testing.T) {
	yes, no := true, false
	cfg := config.GetDefaultConfig()
	cfg.Container.Docker = &yes
	cfg.Security.PasswordlessSudo = &no
	out := captureOutput(t, &os.Stderr, func() { warnDockerHardeningConflict(cfg) })
	if !strings.Contains(out, "[security] passwordless_sudo = false disables Docker support") {
		t.Errorf("warning = %q", out)
	}
	cfg.Security.ReduceKernelSurface = &yes
	out = captureOutput(t, &os.Stderr, func() { warnDockerHardeningConflict(cfg) })
	if !strings.Contains(out, "[security] reduce_kernel_surface = true disables Docker support") {
		t.Errorf("warning = %q", out)
	}
	cfg.Container.Docker = nil
	if out := captureOutput(t, &os.Stderr, func() { warnDockerHardeningConflict(cfg) }); out != "" {
		t.Errorf("no explicit docker = true: want no warning, got %q", out)
	}
}
