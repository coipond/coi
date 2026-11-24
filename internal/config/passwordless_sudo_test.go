package config

import "testing"

// passwordless_sudo defaults on: the image's NOPASSWD rule stays.
func TestPasswordlessSudo_DefaultsOn(t *testing.T) {
	var nilCfg *SecurityConfig
	if !nilCfg.IsPasswordlessSudoEnabled() {
		t.Error("nil security config must keep passwordless sudo")
	}
	if !GetDefaultConfig().Security.IsPasswordlessSudoEnabled() {
		t.Error("default config must keep passwordless sudo")
	}
	no := false
	if (&SecurityConfig{PasswordlessSudo: &no}).IsPasswordlessSudoEnabled() {
		t.Error("passwordless_sudo = false must turn sudo off")
	}
}

// The hardened profile runs without sudo; the default profile keeps it.
func TestPasswordlessSudo_HardenedProfileOff(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Profiles["hardened"] = synthesizeHardenedProfile()
	if err := cfg.ApplyProfile("hardened"); err != nil {
		t.Fatalf("ApplyProfile(hardened): %v", err)
	}
	if cfg.Security.IsPasswordlessSudoEnabled() {
		t.Error("hardened profile must turn passwordless sudo off")
	}

	cfg = GetDefaultConfig()
	cfg.Profiles["default"] = synthesizeDefaultProfile(cfg)
	if err := cfg.ApplyProfile("default"); err != nil {
		t.Fatalf("ApplyProfile(default): %v", err)
	}
	if !cfg.Security.IsPasswordlessSudoEnabled() {
		t.Error("default profile must keep passwordless sudo")
	}
}

// A trusted config can turn sudo back on over a profile that turned it off.
func TestPasswordlessSudo_MergePrecedence(t *testing.T) {
	yes, no := true, false
	dst := &SecurityConfig{PasswordlessSudo: &no}
	mergeSecurityInto(dst, &SecurityConfig{PasswordlessSudo: &yes})
	if !dst.IsPasswordlessSudoEnabled() {
		t.Error("a later passwordless_sudo = true must win")
	}
	mergeSecurityInto(dst, &SecurityConfig{})
	if !dst.IsPasswordlessSudoEnabled() {
		t.Error("an unset passwordless_sudo must not change the merged value")
	}
}

// Untrusted repo config: passwordless_sudo is trusted scope only, in both
// directions.
func TestPasswordlessSudo_UntrustedStripped(t *testing.T) {
	yes, no := true, false
	for _, v := range []*bool{&yes, &no} {
		cfg := &Config{}
		cfg.Security.PasswordlessSudo = v
		sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")
		if cfg.Security.PasswordlessSudo != nil {
			t.Errorf("untrusted passwordless_sudo = %v must be stripped", *v)
		}
	}
}
