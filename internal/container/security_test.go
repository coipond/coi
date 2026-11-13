package container

import (
	"fmt"
	"os/exec"
	"testing"
	"time"
)

func TestContainsPrivilegedValue(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"exact true", "true", true},
		{"true with newline", "true\n", true},
		{"true with whitespace", "  true  ", true},
		{"false", "false", false},
		{"empty string", "", false},
		{"false with newline", "false\n", false},
		{"partial match", "trueish", false},
		{"contains true", "not true", false},
		{"uppercase", "TRUE", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsPrivilegedValue(tt.output)
			if got != tt.want {
				t.Errorf("containsPrivilegedValue(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

// TestIsolateUIDNamespace verifies that IsolateUIDNamespace sets
// security.idmap.isolated=true on a real Incus container.
// Skipped when Incus prerequisites are unavailable.
func TestIsolateUIDNamespace(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found in PATH, skipping integration test")
	}
	if !Available() {
		t.Skip("Incus daemon not available, skipping integration test")
	}
	exists, err := ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("Incus image alias \"coi-default\" not available, skipping integration test")
	}

	name := fmt.Sprintf("coi-test-idmap-%d", time.Now().UnixNano())

	if err := IncusExec("init", "coi-default", name); err != nil {
		t.Fatalf("could not init test container %q: %v", name, err)
	}
	defer func() {
		_ = IncusExecQuiet("delete", name, "--force")
	}()

	if err := IsolateUIDNamespace(name); err != nil {
		t.Fatalf("IsolateUIDNamespace() returned error: %v", err)
	}

	output, err := IncusOutput("config", "get", name, "security.idmap.isolated")
	if err != nil {
		t.Fatalf("failed to read security.idmap.isolated: %v", err)
	}
	if output != "true" {
		t.Errorf("security.idmap.isolated = %q, want %q", output, "true")
	}
}

// TestInitConfigArgsDisableGuestAPI verifies that an `incus init` with
// InitConfigArgs sets security.guestapi=false on a real Incus container.
// Skipped when Incus prerequisites are unavailable.
func TestInitConfigArgsDisableGuestAPI(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found in PATH, skipping integration test")
	}

	// Skip if the Incus daemon is unavailable
	if !Available() {
		t.Skip("Incus daemon not available, skipping integration test")
	}

	// Skip if the required test image alias is unavailable
	exists, err := ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("Incus image alias \"coi-default\" not available, skipping integration test")
	}

	name := fmt.Sprintf("coi-test-guestapi-%d", time.Now().UnixNano())

	// Create a stopped container (init, not start) with the creation config
	args := append([]string{"init", "coi-default", name}, InitConfigArgs(DefaultHardeningPolicy())...)
	if err := IncusExec(args...); err != nil {
		t.Fatalf("could not init test container %q from image %q: %v", name, "coi-default", err)
	}
	defer func() {
		_ = IncusExecQuiet("delete", name, "--force")
	}()

	// Read back the value
	output, err := IncusOutput("config", "get", name, "security.guestapi")
	if err != nil {
		t.Fatalf("failed to read security.guestapi: %v", err)
	}
	if output != "false" {
		t.Errorf("security.guestapi = %q, want %q", output, "false")
	}
}
