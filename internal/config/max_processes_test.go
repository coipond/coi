package config

import "testing"

const maxProcesses500 = "[limits.runtime]\nmax_processes = 500\n"

func assertMaxProcesses(t *testing.T, got *int, want int) {
	t.Helper()
	if got == nil {
		t.Errorf("max_processes unset, want %d", want)
	} else if *got != want {
		t.Errorf("max_processes = %d, want %d", *got, want)
	}
}

func TestMaxProcesses_ExplicitZeroOverridesConfigFile(t *testing.T) {
	cfg := loadWithConfigs(t, maxProcesses500, "[limits.runtime]\nmax_processes = 0\n", nil)
	assertMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 0)
}

func TestMaxProcesses_ExplicitZeroOverridesInAppliedProfile(t *testing.T) {
	cfg := loadWithConfigs(t, maxProcesses500, "", map[string]string{"nolimit": "[limits.runtime]\nmax_processes = 0\n"})
	if err := cfg.ApplyProfile("nolimit"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	assertMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 0)
}

func TestMaxProcesses_ExplicitZeroOverridesParentProfile(t *testing.T) {
	cfg := loadWithConfigs(t, "", "", map[string]string{
		"parent": maxProcesses500,
		"child":  "inherits = \"parent\"\n\n[limits.runtime]\nmax_processes = 0\n",
	})
	assertMaxProcesses(t, cfg.GetProfile("child").Limits.Runtime.MaxProcesses, 0)
	if err := cfg.ApplyProfile("child"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	assertMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 0)
}

// A later layer that does not set max_processes keeps the earlier limit.
func TestMaxProcesses_UnsetKeepsEarlierLimit(t *testing.T) {
	other := "[limits.runtime]\nmax_duration = \"1h\"\n"
	cfg := loadWithConfigs(t, maxProcesses500, other, map[string]string{
		"other":    other,
		"child":    "inherits = \"other500\"\n\n" + other,
		"other500": maxProcesses500,
	})
	assertMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 500)
	assertMaxProcesses(t, cfg.GetProfile("child").Limits.Runtime.MaxProcesses, 500)
	if err := cfg.ApplyProfile("other"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	assertMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 500)
}
