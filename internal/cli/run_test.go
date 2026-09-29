package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/config"
)

func TestDetectRunScript_Absent(t *testing.T) {
	found, err := detectRunScript(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("want found=false in empty workspace")
	}
}

func TestDetectRunScript_Executable(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, runScriptName)
	if err := os.WriteFile(script, []byte("#!/usr/bin/env ruby\nputs 'hi'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	found, err := detectRunScript(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("want found=true for an executable coi-run (any shebang works)")
	}
}

func TestDetectRunScript_NonExecutableIsError(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, runScriptName)
	if err := os.WriteFile(script, []byte("echo hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := detectRunScript(dir)
	if err == nil {
		t.Fatal("want error for a non-executable coi-run (no interpreter guessing)")
	}
	if !strings.Contains(err.Error(), "chmod +x") {
		t.Errorf("error should carry the chmod hint, got: %v", err)
	}
}

func TestDetectRunScript_DirectoryIsError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, runScriptName), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := detectRunScript(dir)
	if err == nil {
		t.Fatal("want error when coi-run is a directory")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error should mention directory, got: %v", err)
	}
}

func TestRemovedFlagHint_ImageAndPersistent(t *testing.T) {
	for _, flag := range []string{"--image", "--persistent"} {
		err := removedFlagHint(nil, errors.New("unknown flag: "+flag))
		if err == nil {
			t.Fatalf("%s: want non-nil error", flag)
		}
		msg := err.Error()
		if !strings.Contains(msg, "flag was removed") || !strings.Contains(msg, "[container]") {
			t.Errorf("%s: want migration hint pointing at [container] config, got: %s", flag, msg)
		}
	}
}

func TestRemovedFlagHint_OtherFlagsUntouched(t *testing.T) {
	orig := errors.New("unknown flag: --bogus")
	err := removedFlagHint(nil, orig)
	if err != orig {
		t.Errorf("unrelated flag errors must pass through unchanged, got: %v", err)
	}
	if removedFlagHint(nil, nil) != nil {
		t.Error("nil error must stay nil")
	}
}

func TestRemovedFlagHint_NoFalsePositiveOnPrefixCollision(t *testing.T) {
	// Regression: substring matching told users "--image was removed" for
	// flags that merely share the prefix. Exact-token matching must pass
	// these through unchanged.
	for _, flag := range []string{
		"--images", "--image-tag", "--imagestore",
		"--persistent-home", "--persistently",
		"--tmux-session", "--tooling", "--timeouts", "--compression-level",
	} {
		orig := errors.New("unknown flag: " + flag)
		if err := removedFlagHint(nil, orig); err != orig {
			t.Errorf("%s: must NOT trigger the migration hint, got: %v", flag, err)
		}
	}
	// But the exact tokens (with typical message shapes) still do.
	for _, msg := range []string{
		"unknown flag: --image",
		"unknown flag: --persistent",
		"unknown flag: --tmux",
		"unknown flag: --tool",
		"unknown flag: --compression",
		"unknown flag: --timeout",
		"flag needs an argument: --image",
	} {
		if err := removedFlagHint(nil, errors.New(msg)); err.Error() == msg {
			t.Errorf("%q: expected the migration hint to be appended", msg)
		}
	}
}

func TestRemovedFlagHint_PointsAtTheRightConfigKey(t *testing.T) {
	cases := map[string]string{
		"--tmux":        "[shell] use_tmux",
		"--tool":        "[tool] name",
		"--compression": "[container.build] compression",
		"--timeout":     "[container] shutdown_timeout",
		"--image":       "[container] image",
		"--persistent":  "[container] persistent",
	}
	for flag, want := range cases {
		err := removedFlagHint(nil, errors.New("unknown flag: "+flag))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: hint must point at %q, got: %v", flag, want, err)
		}
	}
}

func TestDetectRunScript_SymlinkInsideWorkspaceOK(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-script")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, runScriptName)); err != nil {
		t.Fatal(err)
	}

	found, err := detectRunScript(dir)
	if err != nil {
		t.Fatalf("in-workspace symlink should be fine: %v", err)
	}
	if !found {
		t.Error("want found=true for an executable in-workspace symlink target")
	}
}

func TestDetectRunScript_SymlinkEscapingWorkspaceIsError(t *testing.T) {
	// Regression: os.Stat followed the symlink, host detection passed, and
	// the container exec then failed with a raw ENOENT because the target
	// isn't mounted. Must fail fast host-side with an explanation.
	outside := t.TempDir()
	target := filepath.Join(outside, "external-script")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir, runScriptName)); err != nil {
		t.Fatal(err)
	}

	_, err := detectRunScript(dir)
	if err == nil {
		t.Fatal("want error for a symlink resolving outside the workspace")
	}
	if !strings.Contains(err.Error(), "outside the workspace") {
		t.Errorf("error should explain the workspace escape, got: %v", err)
	}
}

func TestDetectRunScript_DanglingSymlinkIsError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, runScriptName)); err != nil {
		t.Fatal(err)
	}

	_, err := detectRunScript(dir)
	if err == nil {
		t.Fatal("want error for a dangling coi-run symlink")
	}
}

func TestOverlayWorkspaceConfig_AppliesPersistent(t *testing.T) {
	// Regression: PersistentPreRunE computes a.persistent before the
	// --workspace project config is overlaid; the overlay must recompute it,
	// or [container] persistent = true in the workspace config is ignored
	// whenever coi run/shell is invoked from outside the workspace.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".coi"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfgContent := "[container]\npersistent = true\n"
	if err := os.WriteFile(filepath.Join(dir, ".coi", "config.toml"), []byte(cfgContent), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{cfg: config.GetDefaultConfig()}
	if err := a.overlayWorkspaceConfig(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.persistent {
		t.Error("persistent from the workspace .coi/config.toml must apply after the overlay")
	}
}

func TestOverlayWorkspaceConfig_ProfileWinsOverWorkspace(t *testing.T) {
	// Regression: the workspace overlay merges the project config on top of
	// the profile applied in PersistentPreRunE; without the container
	// re-apply, /repo/.coi/config.toml would silently override an explicitly
	// requested --profile (and precedence would depend on the invocation
	// directory).
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".coi"), 0o755); err != nil {
		t.Fatal(err)
	}
	wsCfg := "[container]\npersistent = true\nimage = \"ws-image\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".coi", "config.toml"), []byte(wsCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.GetDefaultConfig()
	f := false
	cfg.Profiles["ephemeral-ci"] = config.ProfileConfig{
		Container: config.ContainerConfig{Persistent: &f, Image: "profile-image"},
	}
	if err := cfg.ApplyProfile("ephemeral-ci"); err != nil {
		t.Fatal(err)
	}

	a := &App{cfg: cfg, profile: "ephemeral-ci"}
	if err := a.overlayWorkspaceConfig(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.persistent {
		t.Error("explicit profile's persistent=false must beat the workspace config")
	}
	if got := a.cfg.Container.Image; got != "profile-image" {
		t.Errorf("explicit profile's image must beat the workspace config, got %q", got)
	}
}

func TestResumePersistence(t *testing.T) {
	tr, fa := true, false
	cases := []struct {
		name     string
		cfg      *bool
		metadata bool
		want     bool
	}{
		{"unset config inherits metadata true", nil, true, true},
		{"unset config inherits metadata false", nil, false, false},
		{"explicit true converts ephemeral session", &tr, false, true},
		{"explicit false converts persistent session", &fa, true, false},
		{"explicit matches metadata", &tr, true, true},
	}
	for _, c := range cases {
		if got := resumePersistence(c.cfg, c.metadata); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestDefaultConfig_PersistentUnset(t *testing.T) {
	// The embedded default must leave [container] persistent as a nil pointer
	// ("not configured") — resumePersistence relies on nil to let session
	// metadata win; an explicit default would override metadata on every
	// resume and convert persistent sessions to ephemeral (deleting them).
	cfg := config.GetDefaultConfig()
	if cfg.Container.Persistent != nil {
		t.Fatal("embedded default config must NOT set [container] persistent explicitly")
	}
	if config.BoolVal(cfg.Container.Persistent) {
		t.Fatal("unset persistent must default to false")
	}
}

func TestUpdatePersistentFlag_PreservesAllFields(t *testing.T) {
	// Regression: the previous hand-written JSON dropped profile_name,
	// losing profile inheritance on the next resume after `coi persist`.
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")
	orig := `{
  "session_id": "s1",
  "container_name": "coi-abc-1",
  "persistent": false,
  "profile_name": "rust-dev",
  "workspace": "/w",
  "saved_at": "2026-01-01T00:00:00Z"
}
`
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := updatePersistentFlag(path, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, `"persistent": true`) {
		t.Errorf("persistent flag not updated: %s", content)
	}
	if !strings.Contains(content, `"profile_name": "rust-dev"`) {
		t.Errorf("profile_name must survive the rewrite: %s", content)
	}
	if !strings.Contains(content, `"workspace": "/w"`) {
		t.Errorf("workspace must survive the rewrite: %s", content)
	}
}

func TestResolveImageName_ConfigDriven(t *testing.T) {
	cfg := config.GetDefaultConfig()
	if got := ResolveImageName(cfg); got == "" {
		t.Error("want built-in default image when config sets none")
	}

	cfg.Container.Image = "my-custom"
	if got := ResolveImageName(cfg); got != "my-custom" {
		t.Errorf("want config image to win, got %q", got)
	}
}
