package cli

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/image"
	"github.com/coipond/coi/internal/tool"
)

func TestValidateBuildAgents(t *testing.T) {
	if err := validateBuildAgents(nil); err != nil {
		t.Errorf("empty (all agents) must be valid, got %v", err)
	}
	// Derive the valid case from the registry so this stays honest when a new
	// agent is added (rather than hardcoding the current three).
	if err := validateBuildAgents(tool.ListSupported()); err != nil {
		t.Errorf("all supported agents must be valid, got %v", err)
	}
	err := validateBuildAgents([]string{"claude", "bogus"})
	if err == nil {
		t.Fatal("an unknown agent must be rejected")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error should name the offending agent, got %v", err)
	}
}

func TestEffectiveToolName(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tool.Name = "claude"

	// Nil profile falls back to the top-level config (auto-build path).
	if got := effectiveToolName(cfg, nil); got != "claude" {
		t.Errorf("nil profile should use cfg tool, got %q", got)
	}

	// A profile [tool] name overrides the top-level config.
	p := &config.ProfileConfig{Tool: &config.ToolConfig{Name: "opencode"}}
	if got := effectiveToolName(cfg, p); got != "opencode" {
		t.Errorf("profile tool should override, got %q", got)
	}

	// An empty profile tool name does not clobber the config value.
	p = &config.ProfileConfig{Tool: &config.ToolConfig{Name: ""}}
	if got := effectiveToolName(cfg, p); got != "claude" {
		t.Errorf("empty profile tool should fall back to cfg, got %q", got)
	}

	// Nothing configured anywhere defaults to claude.
	if got := effectiveToolName(&config.Config{}, nil); got != "claude" {
		t.Errorf("unset tool should default to claude, got %q", got)
	}
}

func TestPrepareBuildAgents(t *testing.T) {
	// Empty selection installs the default agent set — always valid, and never
	// warns when the configured tool is in that set (claude is).
	if err := prepareBuildAgents(nil, "claude"); err != nil {
		t.Errorf("empty agents must be valid, got %v", err)
	}

	// An unknown agent is a hard error (fail fast, before any build).
	if err := prepareBuildAgents([]string{"bogus"}, "claude"); err == nil {
		t.Fatal("unknown agent must error")
	}

	// A selection that includes the configured tool is fine (warn is non-fatal
	// anyway; here it must not fire and must not error).
	if err := prepareBuildAgents([]string{"claude", "pi"}, "claude"); err != nil {
		t.Errorf("valid selection must not error, got %v", err)
	}

	// A selection that omits the configured tool warns but is non-fatal.
	if err := prepareBuildAgents([]string{"opencode"}, "claude"); err != nil {
		t.Errorf("omitting the tool must warn, not error, got %v", err)
	}

	// An EMPTY selection installs the default agent set, which excludes opt-in
	// agents (#698): a codex user with no explicit agents list still gets an
	// image without their tool, so the footgun warning must fire (non-fatal).
	if err := prepareBuildAgents(nil, "codex"); err != nil {
		t.Errorf("empty agents with an opt-in tool must warn, not error, got %v", err)
	}

	// Explicitly selecting the opt-in agent alongside its tool is clean.
	if err := prepareBuildAgents([]string{"claude", "codex"}, "codex"); err != nil {
		t.Errorf("explicit codex selection must not error, got %v", err)
	}
}

// coiImageBuildOptions carries the profile's [container.build] settings —
// compression, base, agents — into the coi default image build, for both
// `coi build` and `coi build --all`.
func TestCoiImageBuildOptions(t *testing.T) {
	p := &config.ProfileConfig{}
	p.Container.Build.Compression = "none"
	p.Container.Build.Agents = []string{"claude"}
	opts := coiImageBuildOptions(p, true, "fast", nil)
	if opts.Compression != "none" || opts.StoragePool != "fast" || !opts.Force ||
		opts.ImageType != "coi" || opts.AliasName != image.CoiAlias || opts.BaseImage != image.BaseImage ||
		len(opts.Agents) != 1 {
		t.Errorf("unexpected options: %+v", opts)
	}

	p.Container.Build.Base = "images:ubuntu/24.04/cloud"
	if got := coiImageBuildOptions(p, false, "", nil).BaseImage; got != "images:ubuntu/24.04/cloud" {
		t.Errorf("base override not applied: %q", got)
	}
}
