package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func boolPtr(b bool) *bool { return &b }

// Keep every test in this package hermetic: when the suite runs inside a real
// Colima/Lima/OrbStack VM, the default seam would read the developer's actual
// Mac gitconfig. Tests that exercise the Mac path set it explicitly.
func init() { macHostHome = func() string { return "" } }

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

// setupGuestAndMacHome points the guest's global gitconfig at a temp file with a
// "Guest VM" identity and returns an empty fake Mac home that macHostHome
// resolves to for the duration of the test.
func setupGuestAndMacHome(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	dir := t.TempDir()
	guest := filepath.Join(dir, "guest-gitconfig")
	writeFile(t, guest, "[user]\n\tname = Guest VM\n\temail = vm@example.com\n")
	t.Setenv("GIT_CONFIG_GLOBAL", guest)

	mac := filepath.Join(dir, "Users", "alice")
	if err := os.MkdirAll(mac, 0o755); err != nil {
		t.Fatal(err)
	}
	orig := macHostHome
	t.Cleanup(func() { macHostHome = orig })
	macHostHome = func() string { return mac }
	return mac
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Inside a Mac VM the guest's global gitconfig is not the user's; the Mac
// home's gitconfig must win (even though GIT_CONFIG_GLOBAL points at the guest
// file — that override belongs to the guest and is dropped for the Mac read).
func TestResolveGitIdentityPrefersMacHostConfig(t *testing.T) {
	mac := setupGuestAndMacHome(t)
	writeFile(t, filepath.Join(mac, ".gitconfig"), "[user]\n\tname = Mac User\n\temail = mac@example.com\n")

	got := resolveGitIdentity(&config.GitConfig{})
	if got.Name != "Mac User" || got.Email != "mac@example.com" {
		t.Fatalf("Mac identity should win, got %+v", got)
	}
}

// An incomplete Mac identity must not be mixed with the guest's: the guest
// identity is used whole.
func TestResolveGitIdentityIncompleteMacFallsBackWholly(t *testing.T) {
	mac := setupGuestAndMacHome(t)
	writeFile(t, filepath.Join(mac, ".gitconfig"), "[user]\n\tname = Only Name\n")

	got := resolveGitIdentity(&config.GitConfig{})
	if got.Name != "Guest VM" || got.Email != "vm@example.com" {
		t.Fatalf("incomplete Mac identity should fall back wholly to the guest, got %+v", got)
	}
}

// include.path = ~/... must resolve against the MAC home, not the guest's — the
// common "split personal config" setup.
func TestResolveGitIdentityMacIncludeTildeResolvesAgainstMacHome(t *testing.T) {
	mac := setupGuestAndMacHome(t)
	writeFile(t, filepath.Join(mac, ".gitconfig"), "[include]\n\tpath = ~/.gitconfig-personal\n")
	writeFile(t, filepath.Join(mac, ".gitconfig-personal"), "[user]\n\tname = Mac Included\n\temail = included@example.com\n")

	got := resolveGitIdentity(&config.GitConfig{})
	if got.Name != "Mac Included" || got.Email != "included@example.com" {
		t.Fatalf("~ in include.path should resolve against the Mac home, got %+v", got)
	}
}

// With no ~/.gitconfig, git's --global falls back to the XDG file; the Mac
// home's XDG config must be honored the same way.
func TestResolveGitIdentityMacXDGConfig(t *testing.T) {
	mac := setupGuestAndMacHome(t)
	writeFile(t, filepath.Join(mac, ".config", "git", "config"), "[user]\n\tname = Mac XDG\n\temail = xdg@example.com\n")

	got := resolveGitIdentity(&config.GitConfig{})
	if got.Name != "Mac XDG" || got.Email != "xdg@example.com" {
		t.Fatalf("Mac XDG config should be used, got %+v", got)
	}
}

// Explicit [git] identity and seed_host_identity=false still win over the Mac
// home, exactly as before.
func TestResolveGitIdentityMacHomeRespectsExplicitAndSeedOff(t *testing.T) {
	mac := setupGuestAndMacHome(t)
	writeFile(t, filepath.Join(mac, ".gitconfig"), "[user]\n\tname = Mac User\n\temail = mac@example.com\n")

	explicit := resolveGitIdentity(&config.GitConfig{Name: "Pinned", Email: "pinned@example.com"})
	if explicit.Name != "Pinned" || explicit.Email != "pinned@example.com" {
		t.Fatalf("explicit identity should win, got %+v", explicit)
	}
	if got := resolveGitIdentity(&config.GitConfig{SeedHostIdentity: boolPtr(false)}); got.Complete() {
		t.Fatalf("seed_host_identity=false must not seed from the Mac home, got %+v", got)
	}
}
