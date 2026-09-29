package cli

import (
	"path/filepath"
	"testing"

	"github.com/mensfeld/coi/internal/config"
)

func TestParseCredentialConfig_Empty(t *testing.T) {
	cc, err := ParseCredentialConfig(&config.Config{})
	if err != nil {
		t.Fatalf("ParseCredentialConfig: %v", err)
	}
	if len(cc.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(cc.Entries))
	}
}

func TestParseCredentialConfig_BundleExpandsToFilesAndStateFile(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	cfg := &config.Config{
		Credentials: []config.CredentialEntry{{Bundle: "claude"}},
	}
	cc, err := ParseCredentialConfig(cfg)
	if err != nil {
		t.Fatalf("ParseCredentialConfig: %v", err)
	}
	// claude bundle: 4 essential files + 1 state file (.claude.json) = 5 entries.
	if len(cc.Entries) != 5 {
		t.Fatalf("expected 5 entries for claude bundle, got %d: %+v", len(cc.Entries), cc.Entries)
	}
	for _, e := range cc.Entries {
		if e.BundleName != "claude" {
			t.Errorf("BundleName = %q, want %q", e.BundleName, "claude")
		}
		if !filepath.IsAbs(e.HostPath) {
			t.Errorf("HostPath not absolute: %q", e.HostPath)
		}
	}
	foundState := false
	for _, e := range cc.Entries {
		if e.ContainerPath == ".claude.json" {
			foundState = true
		}
	}
	if !foundState {
		t.Errorf("expected a .claude.json state-file entry, got %+v", cc.Entries)
	}
}

func TestParseCredentialConfig_BundleAppliesModeAndContainerPath(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	cfg := &config.Config{Credentials: []config.CredentialEntry{{Bundle: "ollama"}}}
	cc, err := ParseCredentialConfig(cfg)
	if err != nil {
		t.Fatalf("ParseCredentialConfig: %v", err)
	}
	if len(cc.Entries) != 1 {
		t.Fatalf("expected 1 entry for ollama bundle, got %d", len(cc.Entries))
	}
	e := cc.Entries[0]
	if e.Mode != "0600" {
		t.Errorf("Mode = %q, want %q", e.Mode, "0600")
	}
	wantContainer := filepath.Join(".ollama", "id_ed25519")
	if e.ContainerPath != wantContainer {
		t.Errorf("ContainerPath = %q, want %q", e.ContainerPath, wantContainer)
	}
	if filepath.IsAbs(e.ContainerPath) {
		t.Error("bundle-sourced ContainerPath should be home-relative, not absolute")
	}
	wantHost := filepath.Join("/home/tester", ".ollama", "id_ed25519")
	if e.HostPath != wantHost {
		t.Errorf("HostPath = %q, want %q", e.HostPath, wantHost)
	}
}

func TestParseCredentialConfig_UnknownBundleErrors(t *testing.T) {
	cfg := &config.Config{Credentials: []config.CredentialEntry{{Bundle: "not-a-bundle"}}}
	if _, err := ParseCredentialConfig(cfg); err == nil {
		t.Fatal("expected error for unknown bundle name")
	}
}

func TestParseCredentialConfig_AdHocExpandsAndCarriesTrustFields(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	cfg := &config.Config{
		Credentials: []config.CredentialEntry{
			{Host: "~/.aws/credentials", Container: "/home/code/.aws/credentials", Mode: "0600", Untrusted: true, SourcePath: "/ws/.coi/config.toml"},
		},
	}
	cc, err := ParseCredentialConfig(cfg)
	if err != nil {
		t.Fatalf("ParseCredentialConfig: %v", err)
	}
	if len(cc.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cc.Entries))
	}
	e := cc.Entries[0]
	if e.HostPath != "/home/tester/.aws/credentials" {
		t.Errorf("HostPath = %q, want expanded", e.HostPath)
	}
	if e.ContainerPath != "/home/code/.aws/credentials" {
		t.Errorf("ContainerPath = %q, want %q", e.ContainerPath, "/home/code/.aws/credentials")
	}
	if e.BundleName != "" {
		t.Errorf("BundleName = %q, want empty for ad-hoc entry", e.BundleName)
	}
	if !e.Untrusted || e.SourcePath != "/ws/.coi/config.toml" {
		t.Errorf("trust metadata not carried: %+v", e)
	}
}

func TestParseCredentialConfig_AdHocRejectsRelativeContainerPath(t *testing.T) {
	cfg := &config.Config{
		Credentials: []config.CredentialEntry{{Host: "/abs/host", Container: "relative/path"}},
	}
	if _, err := ParseCredentialConfig(cfg); err == nil {
		t.Fatal("expected error for relative container path")
	}
}
