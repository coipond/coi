package cli

import (
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/config"
	"github.com/spf13/cobra"
)

// newProfileTestApp builds an App whose config carries the given profiles and
// [defaults] profile, plus a cobra command exposing the --profile flag bound to
// App.profile (mirroring root.go), so applyDefaultProfileFallback can be
// exercised without a container or the full command tree.
func newProfileTestApp(defaultProfile string, profiles map[string]config.ProfileConfig) (*App, *cobra.Command) {
	cfg := config.GetDefaultConfig()
	cfg.Profiles = profiles
	cfg.Defaults.Profile = defaultProfile
	a := &App{cfg: cfg}
	cmd := &cobra.Command{Use: "shell"}
	cmd.Flags().StringVar(&a.profile, "profile", "", "")
	return a, cmd
}

func profileWithImage(img string) config.ProfileConfig {
	var p config.ProfileConfig
	p.Container.Image = img
	return p
}

// The common case: nothing else chose a profile, so [defaults] profile applies.
func TestApplyDefaultProfileFallback_AppliesWhenNothingChosen(t *testing.T) {
	a, cmd := newProfileTestApp("p", map[string]config.ProfileConfig{"p": profileWithImage("coi-p")})

	applied, err := a.applyDefaultProfileFallback(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !applied {
		t.Fatal("expected the default profile to be applied")
	}
	if a.profile != "p" {
		t.Errorf("a.profile = %q, want %q", a.profile, "p")
	}
	if a.cfg.Container.Image != "coi-p" {
		t.Errorf("Container.Image = %q, want the profile's image %q", a.cfg.Container.Image, "coi-p")
	}
}

// Precedence: a profile already chosen by an alias or resume metadata (a.profile
// set) must win, and the default must NOT be merged on top of it — the additive
// merge would otherwise duplicate/stack the two profiles' slices.
func TestApplyDefaultProfileFallback_SkipsWhenProfileAlreadyChosen(t *testing.T) {
	a, cmd := newProfileTestApp("p", map[string]config.ProfileConfig{
		"p":      profileWithImage("coi-p"),
		"chosen": profileWithImage("coi-chosen"),
	})
	a.profile = "chosen" // stands in for an alias/resume-applied profile

	applied, err := a.applyDefaultProfileFallback(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if applied {
		t.Fatal("must not apply the default on top of an already-chosen profile (no stacking)")
	}
	if a.profile != "chosen" {
		t.Errorf("a.profile = %q, want it left as %q", a.profile, "chosen")
	}
	if a.cfg.Container.Image == "coi-p" {
		t.Error("the default profile must not have been merged over the chosen one")
	}
}

// An explicit --profile flag (Changed) suppresses the default fallback.
func TestApplyDefaultProfileFallback_SkipsWhenFlagChanged(t *testing.T) {
	a, cmd := newProfileTestApp("p", map[string]config.ProfileConfig{"p": profileWithImage("coi-p")})
	if err := cmd.Flags().Set("profile", "explicit"); err != nil { // marks Changed + sets a.profile
		t.Fatal(err)
	}

	applied, err := a.applyDefaultProfileFallback(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if applied {
		t.Fatal("an explicit --profile must suppress the default fallback")
	}
}

// No [defaults] profile configured: a clean no-op, nothing applied.
func TestApplyDefaultProfileFallback_NoDefaultConfigured(t *testing.T) {
	a, cmd := newProfileTestApp("", nil)

	applied, err := a.applyDefaultProfileFallback(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if applied {
		t.Fatal("no [defaults] profile means no fallback")
	}
}

// A [defaults] profile naming an unknown profile is the single guard's job: it
// errors at the apply site with an actionable message (not ApplyProfile's terser
// wording), and only for commands that reach this fallback (coi shell/run) — so
// unrelated commands never hit it.
func TestApplyDefaultProfileFallback_MissingProfileErrors(t *testing.T) {
	a, cmd := newProfileTestApp("ghost", map[string]config.ProfileConfig{})

	if _, err := a.applyDefaultProfileFallback(cmd); err == nil {
		t.Fatal("a default profile that names no known profile must error")
	} else if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should name the missing profile, got: %v", err)
	} else if !strings.Contains(err.Error(), "profile list") {
		t.Errorf("error should point the user at `coi profile list`, got: %v", err)
	}
}
