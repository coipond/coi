package cli

import (
	"os/exec"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func boolPtr(b bool) *bool { return &b }

func TestResolveGitIdentityFromHostGlobalConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	configPath := t.TempDir() + "/gitconfig"
	t.Setenv("GIT_CONFIG_GLOBAL", configPath)

	if err := exec.Command("git", "config", "--global", "user.name", "Host User").Run(); err != nil {
		t.Fatalf("set user.name: %v", err)
	}
	if err := exec.Command("git", "config", "--global", "user.email", "host@example.com").Run(); err != nil {
		t.Fatalf("set user.email: %v", err)
	}

	got := resolveGitIdentity(&config.GitConfig{})
	if got.Name != "Host User" || got.Email != "host@example.com" {
		t.Fatalf("identity = %+v", got)
	}
}

func TestResolveGitIdentityRequiresNameAndEmail(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	configPath := t.TempDir() + "/gitconfig"
	t.Setenv("GIT_CONFIG_GLOBAL", configPath)

	if err := exec.Command("git", "config", "--global", "user.name", "Host User").Run(); err != nil {
		t.Fatalf("set user.name: %v", err)
	}

	got := resolveGitIdentity(&config.GitConfig{})
	if got.Name != "" || got.Email != "" {
		t.Fatalf("incomplete identity should be dropped, got %+v", got)
	}
}

// An explicit [git] name/email overrides the host global config.
func TestResolveGitIdentityExplicitOverridesHost(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	configPath := t.TempDir() + "/gitconfig"
	t.Setenv("GIT_CONFIG_GLOBAL", configPath)
	if err := exec.Command("git", "config", "--global", "user.name", "Host User").Run(); err != nil {
		t.Fatalf("set user.name: %v", err)
	}
	if err := exec.Command("git", "config", "--global", "user.email", "host@example.com").Run(); err != nil {
		t.Fatalf("set user.email: %v", err)
	}

	got := resolveGitIdentity(&config.GitConfig{Name: "Jane Dev", Email: "jane@corp.example"})
	if got.Name != "Jane Dev" || got.Email != "jane@corp.example" {
		t.Fatalf("explicit identity should win, got %+v", got)
	}
}

// A partial explicit identity (name only) is not complete, so it falls back to
// the host global config rather than seeding a half-identity.
func TestResolveGitIdentityPartialExplicitFallsBackToHost(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	configPath := t.TempDir() + "/gitconfig"
	t.Setenv("GIT_CONFIG_GLOBAL", configPath)
	if err := exec.Command("git", "config", "--global", "user.name", "Host User").Run(); err != nil {
		t.Fatalf("set user.name: %v", err)
	}
	if err := exec.Command("git", "config", "--global", "user.email", "host@example.com").Run(); err != nil {
		t.Fatalf("set user.email: %v", err)
	}

	got := resolveGitIdentity(&config.GitConfig{Name: "Jane Dev"})
	if got.Name != "Host User" || got.Email != "host@example.com" {
		t.Fatalf("partial explicit should fall back to host, got %+v", got)
	}
}

// seed_host_identity=false suppresses host-global seeding: no explicit identity
// means nothing is seeded even when the host has a global identity.
func TestResolveGitIdentitySeedDisabledSkipsHost(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	configPath := t.TempDir() + "/gitconfig"
	t.Setenv("GIT_CONFIG_GLOBAL", configPath)
	if err := exec.Command("git", "config", "--global", "user.name", "Host User").Run(); err != nil {
		t.Fatalf("set user.name: %v", err)
	}
	if err := exec.Command("git", "config", "--global", "user.email", "host@example.com").Run(); err != nil {
		t.Fatalf("set user.email: %v", err)
	}

	got := resolveGitIdentity(&config.GitConfig{SeedHostIdentity: boolPtr(false)})
	if got.Name != "" || got.Email != "" {
		t.Fatalf("host seeding disabled should yield empty identity, got %+v", got)
	}

	// ...but an explicit identity is still honored even with seeding off.
	got = resolveGitIdentity(&config.GitConfig{
		SeedHostIdentity: boolPtr(false),
		Name:             "Jane Dev",
		Email:            "jane@corp.example",
	})
	if got.Name != "Jane Dev" || got.Email != "jane@corp.example" {
		t.Fatalf("explicit identity should survive seed=false, got %+v", got)
	}
}
