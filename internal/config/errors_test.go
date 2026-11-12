package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("bad toml")

	withPath := &ConfigError{Path: "/etc/coi/config.toml", Err: inner}
	if !strings.Contains(withPath.Error(), "/etc/coi/config.toml") || !strings.Contains(withPath.Error(), "bad toml") {
		t.Errorf("Error() should mention path and cause, got %q", withPath.Error())
	}
	if !errors.Is(withPath, inner) {
		t.Error("Unwrap must expose the wrapped cause")
	}

	noPath := &ConfigError{Err: inner}
	if strings.Contains(noPath.Error(), "()") {
		t.Errorf("empty path must not render empty parens, got %q", noPath.Error())
	}
}

// A parse failure from Load must surface as a *ConfigError so the CLI can map
// it to a config-specific exit code.
func TestLoad_WrapsParseFailureAsConfigError(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(bad, []byte("this is = not valid toml ][\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COI_CONFIG", bad)

	_, err := Load()
	if err == nil {
		t.Fatal("expected Load to fail on malformed config")
	}
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("Load error must be *ConfigError, got %T: %v", err, err)
	}
}

// A workspace config loaded by OverlayProjectConfig (coi run/shell --workspace
// from another directory, alias launch) must fail like one Load reads.
func TestOverlayProjectConfig_WrapsFailureAsConfigError(t *testing.T) {
	cases := map[string]string{
		"parse error":   "this is = not valid toml ][\n",
		"non-IP listen": "[[ports.map]]\nname = \"web\"\ncontainer = 8000\nlisten = \"localhost\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ws := t.TempDir()
			if err := os.MkdirAll(filepath.Join(ws, ".coi"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ws, ".coi", "config.toml"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}

			err := GetDefaultConfig().OverlayProjectConfig(ws)
			var cfgErr *ConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("OverlayProjectConfig error must be *ConfigError, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "failed to load project config from "+ws) {
				t.Errorf("error should name the workspace, got %q", err.Error())
			}
		})
	}
}

// A workspace without .coi/config.toml is not an error.
func TestOverlayProjectConfig_MissingFileIsNoError(t *testing.T) {
	if err := GetDefaultConfig().OverlayProjectConfig(t.TempDir()); err != nil {
		t.Fatalf("missing project config must not fail, got %v", err)
	}
}
