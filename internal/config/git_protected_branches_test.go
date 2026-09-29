package config

import (
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
)

// The branch guard is ON by default: an absent field resolves to
// ["main","master"], the same secure-by-default stance as strip_attribution.
func TestGitProtectedBranches_Defaults(t *testing.T) {
	cfg := GetDefaultConfig()
	if got := cfg.Git.EffectiveProtectedBranches(); !reflect.DeepEqual(got, []string{"main", "master"}) {
		t.Errorf("default protected_branches = %v, want [main master]", got)
	}
	var nilCfg *GitConfig
	if got := nilCfg.EffectiveProtectedBranches(); !reflect.DeepEqual(got, []string{"main", "master"}) {
		t.Errorf("nil receiver = %v, want [main master]", got)
	}
	// The returned slice is a copy: mutating it must not corrupt the package default.
	got := nilCfg.EffectiveProtectedBranches()
	got[0] = "tampered"
	if again := nilCfg.EffectiveProtectedBranches(); again[0] != "main" {
		t.Errorf("EffectiveProtectedBranches leaked its backing array: %v", again)
	}
}

// A configured list is used verbatim; an explicit empty list DISABLES the guard
// (distinct from an absent field, which inherits the default).
func TestGitProtectedBranches_TOMLParse(t *testing.T) {
	t.Run("custom list", func(t *testing.T) {
		var cfg Config
		if _, err := toml.Decode(`
[git]
protected_branches = ["main", "release", "prod"]
`, &cfg); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got := cfg.Git.EffectiveProtectedBranches(); !reflect.DeepEqual(got, []string{"main", "release", "prod"}) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("explicit empty disables", func(t *testing.T) {
		var cfg Config
		if _, err := toml.Decode(`
[git]
protected_branches = []
`, &cfg); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if cfg.Git.ProtectedBranches == nil {
			t.Fatal("explicit `protected_branches = []` must decode to a non-nil pointer (tri-state)")
		}
		if got := cfg.Git.EffectiveProtectedBranches(); len(got) != 0 {
			t.Errorf("explicit [] should disable the guard, got %v", got)
		}
	})

	t.Run("absent inherits default", func(t *testing.T) {
		var cfg Config
		if _, err := toml.Decode("[git]\n", &cfg); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if cfg.Git.ProtectedBranches != nil {
			t.Error("absent field must stay nil")
		}
		if got := cfg.Git.EffectiveProtectedBranches(); !reflect.DeepEqual(got, []string{"main", "master"}) {
			t.Errorf("absent field should inherit default, got %v", got)
		}
	})
}

// Pointer merge (not len-based): a later scope can both replace the list AND
// disable the guard with an explicit empty list.
func TestGitProtectedBranches_Merge(t *testing.T) {
	base := GetDefaultConfig() // default → [main master]
	custom := []string{"trunk"}
	overlay := &Config{}
	overlay.Git.ProtectedBranches = &custom
	base.Merge(overlay)
	if got := base.Git.EffectiveProtectedBranches(); !reflect.DeepEqual(got, []string{"trunk"}) {
		t.Errorf("overlay list should win, got %v", got)
	}

	// An explicit empty list from a later scope disables the guard — this is the
	// case a `len(src) > 0` merge would silently drop.
	empty := []string{}
	overlay2 := &Config{}
	overlay2.Git.ProtectedBranches = &empty
	base.Merge(overlay2)
	if got := base.Git.EffectiveProtectedBranches(); len(got) != 0 {
		t.Errorf("overlay [] should disable the guard, got %v", got)
	}

	// A scope that does not mention the field leaves the current value untouched.
	base2 := GetDefaultConfig()
	base2.Merge(&Config{})
	if got := base2.Git.EffectiveProtectedBranches(); !reflect.DeepEqual(got, []string{"main", "master"}) {
		t.Errorf("absent overlay field must not clobber, got %v", got)
	}
}

// The guard is an enforcement control: an untrusted project config cannot shrink
// or empty it. Nil-ing it out falls back to the default, so the guard stays on.
func TestSanitizeUntrusted_GitProtectedBranches(t *testing.T) {
	// A malicious project config trying to disable the guard.
	disable := []string{}
	cfg := &Config{}
	cfg.Git.ProtectedBranches = &disable
	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")
	if cfg.Git.ProtectedBranches != nil {
		t.Error("untrusted protected_branches must be stripped to nil")
	}
	if got := cfg.Git.EffectiveProtectedBranches(); !reflect.DeepEqual(got, []string{"main", "master"}) {
		t.Errorf("after sanitize the default guard must remain, got %v", got)
	}

	// A project config trying to REPLACE the set is also rejected (trusted-scope).
	custom := []string{"only-this"}
	cfg = &Config{}
	cfg.Git.ProtectedBranches = &custom
	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")
	if cfg.Git.ProtectedBranches != nil {
		t.Error("untrusted protected_branches override must be stripped")
	}
}
