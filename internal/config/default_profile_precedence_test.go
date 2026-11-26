package config

import "testing"

// TestProfilePrecedence_ExplicitVsDefault_Pinned pins the (intentional, known)
// precedence difference between selecting a profile via an explicit `--profile`
// and via `[defaults] profile` when a workspace project config overlays fields
// the profile also sets. This is "finding 4" from the #607 review: it is not a
// crash and only surfaces when the launch dir differs from the workspace (so a
// second, workspace-scoped project config is overlaid), but the two paths apply
// the profile at DIFFERENT points in the merge chain:
//
//	explicit --profile : ApplyProfile → (workspace overlay) Merge →
//	                     ReapplyProfileContainer, ReapplyProfileNetwork
//	[defaults] profile : (workspace overlay) Merge → ApplyProfile
//
// (See internal/cli: root.go applies an explicit --profile before
// overlayWorkspaceConfig, which then re-wins only [container] and [network]
// via ReapplyProfileContainer and ReapplyProfileNetwork;
// applyDefaultProfileFallback applies the default profile AFTER that
// overlay.)
//
// Pinned consequences, so any future change to the merge order is a deliberate
// decision rather than a silent behavior shift:
//   - [container] and [network] fields: the profile wins in BOTH paths
//     ([network]: for a profile copying the config's, only what the profile
//     sets itself, see ReapplyProfileNetwork).
//   - other sections (here: tool.claude.model): the workspace overlay wins for
//     an explicit --profile, but the profile wins for [defaults] profile.
//
// Security-relevant downgrades never reach this divergence: an untrusted
// workspace config is sanitized (network/security/git stripped) before the
// overlay, so only benign fields like `tool.claude.model`/`timezone` can differ.
func TestProfilePrecedence_ExplicitVsDefault_Pinned(t *testing.T) {
	profileWork := ProfileConfig{Tool: &ToolConfig{Claude: ClaudeToolConfig{Model: "profile-model"}}}
	profileWork.Container.Image = "coi-work"

	newBase := func() *Config {
		c := GetDefaultConfig()
		c.Profiles = map[string]ProfileConfig{"work": profileWork}
		return c
	}
	// The (sanitized) workspace .coi/config.toml overlay: it sets both a
	// non-[container] field and a [container] field that the profile also sets.
	newOverlay := func() *Config {
		o := &Config{}
		o.Tool.Claude.Model = "project-model"
		o.Container.Image = "coi-project"
		return o
	}

	// Explicit `--profile work`: profile first, then the workspace overlay, then
	// [container] re-won.
	explicit := newBase()
	if err := explicit.ApplyProfile("work"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	explicit.Merge(newOverlay())
	if err := explicit.ReapplyProfileContainer("work"); err != nil {
		t.Fatalf("ReapplyProfileContainer: %v", err)
	}

	// `[defaults] profile = work`: the workspace overlay first, then the profile.
	def := newBase()
	def.Merge(newOverlay())
	if err := def.ApplyProfile("work"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}

	// Consistent part: [container] is the profile's in BOTH paths.
	if explicit.Container.Image != "coi-work" {
		t.Errorf("explicit --profile: [container] image should be the profile's %q, got %q", "coi-work", explicit.Container.Image)
	}
	if def.Container.Image != "coi-work" {
		t.Errorf("[defaults] profile: [container] image should be the profile's %q, got %q", "coi-work", def.Container.Image)
	}

	// Divergent part (finding 4): a non-[container] field the overlay also sets.
	if explicit.Tool.Claude.Model != "project-model" {
		t.Errorf("explicit --profile: the workspace overlay should win model (applied after the profile), got %q", explicit.Tool.Claude.Model)
	}
	if def.Tool.Claude.Model != "profile-model" {
		t.Errorf("[defaults] profile: the profile should win model (applied after the overlay), got %q", def.Tool.Claude.Model)
	}

	// The whole point of this test: the two selection paths intentionally diverge
	// on non-[container] fields today. If they ever agree, that is a behavior
	// change to reconcile deliberately (update the docs/decision) — not an
	// assertion to quietly delete.
	if explicit.Tool.Claude.Model == def.Tool.Claude.Model {
		t.Fatalf("explicit and [defaults] profile now agree on model (%q); "+
			"the known precedence divergence changed — reconcile the decision, don't just drop this test",
			def.Tool.Claude.Model)
	}
}
