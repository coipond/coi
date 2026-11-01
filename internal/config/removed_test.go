package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coischema "github.com/coipond/coi/schema"
)

const removedNetworkLoggingTOML = `
[network]
mode = "open"

[network.logging]
enabled = true
path = "~/.coi/logs/network.log"
`

const noNetworkLoggingTOML = `
[network]
mode = "open"
`

// captureStderr returns what fn writes to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wp
	defer func() { os.Stderr = old }()

	fn()

	_ = wp.Close()
	os.Stderr = old
	data, _ := io.ReadAll(rp)
	return string(data)
}

func assertNetworkLoggingWarnings(t *testing.T, stderr, path string, want int) {
	t.Helper()
	if got := strings.Count(stderr, "[network.logging]"); got != want {
		t.Fatalf("got %d [network.logging] warnings, want %d; stderr: %q", got, want, stderr)
	}
	if want > 0 && !strings.Contains(stderr, path) {
		t.Errorf("warning does not name %s: %q", path, stderr)
	}
}

func TestLoadConfigFileScoped_RemovedNetworkLogging(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    int
	}{
		{"set", removedNetworkLoggingTOML, 1},
		{"unset", noNetworkLoggingTOML, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTOML(t, t.TempDir(), "config.toml", tc.content)
			cfg := GetDefaultConfig()
			stderr := captureStderr(t, func() {
				if err := loadConfigFileScoped(cfg, path, true); err != nil {
					t.Errorf("loadConfigFileScoped: %v", err)
				}
			})
			assertNetworkLoggingWarnings(t, stderr, path, tc.want)
			if cfg.Network.Mode != NetworkModeOpen {
				t.Errorf("rest of [network] not applied: mode = %q", cfg.Network.Mode)
			}
		})
	}
}

func TestLoadProfileDirectories_RemovedNetworkLogging(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    int
	}{
		{"set", removedNetworkLoggingTOML, 1},
		{"unset", noNetworkLoggingTOML, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			profileDir := filepath.Join(dir, "profiles", "netlog")
			if err := os.MkdirAll(profileDir, 0o755); err != nil {
				t.Fatal(err)
			}
			path := writeTOML(t, profileDir, "config.toml", tc.content)
			cfg := GetDefaultConfig()
			stderr := captureStderr(t, func() {
				if err := loadProfileDirectories(cfg, dir, true); err != nil {
					t.Errorf("loadProfileDirectories: %v", err)
				}
			})
			assertNetworkLoggingWarnings(t, stderr, path, tc.want)
			profile, ok := cfg.Profiles["netlog"]
			if !ok {
				t.Fatal("profile netlog was not loaded")
			}
			if profile.Network == nil || profile.Network.Mode != NetworkModeOpen {
				t.Errorf("rest of [network] not applied: %+v", profile.Network)
			}
		})
	}
}

// The schema rejects the section, so it must be dropped before validation.
func TestDropRemovedProfileKeys_ProfilePassesSchema(t *testing.T) {
	raw := map[string]any{
		"network": map[string]any{
			"mode":    "open",
			"logging": map[string]any{"enabled": true},
		},
	}
	if err := coischema.ValidateProfileMap(raw); err == nil {
		t.Fatal("schema accepted [network.logging]; it should be removed from the schema")
	}
	stderr := captureStderr(t, func() { DropRemovedProfileKeys(raw, "p.toml") })
	assertNetworkLoggingWarnings(t, stderr, "p.toml", 1)
	if err := coischema.ValidateProfileMap(raw); err != nil {
		t.Errorf("profile without [network.logging] failed schema validation: %v", err)
	}
}
