package session

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/network"
)

func TestConfigureOptions_ContainerNameRequired(t *testing.T) {
	opts := ConfigureOptions{}
	_, err := ConfigureContainer(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error when container name is empty")
	}
	if err.Error() != "container name is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigureResultJSON(t *testing.T) {
	result := &ConfigureResult{
		SSHAgentSocketPath: "/tmp/ssh-agent.sock",
		Timezone:           "Europe/Warsaw",
		NetworkApplied:     "restricted",
		HomeDir:            "/home/code",
	}

	jsonStr, err := ConfigureResultJSON(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON and round-trips correctly
	var parsed ConfigureResult
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if parsed.SSHAgentSocketPath != result.SSHAgentSocketPath {
		t.Errorf("SSHAgentSocketPath: got %q, want %q", parsed.SSHAgentSocketPath, result.SSHAgentSocketPath)
	}
	if parsed.Timezone != result.Timezone {
		t.Errorf("Timezone: got %q, want %q", parsed.Timezone, result.Timezone)
	}
	if parsed.NetworkApplied != result.NetworkApplied {
		t.Errorf("NetworkApplied: got %q, want %q", parsed.NetworkApplied, result.NetworkApplied)
	}
	if parsed.HomeDir != result.HomeDir {
		t.Errorf("HomeDir: got %q, want %q", parsed.HomeDir, result.HomeDir)
	}
}

func TestConfigureResultJSON_OmitsEmpty(t *testing.T) {
	result := &ConfigureResult{
		HomeDir: "/home/code",
	}

	jsonStr, err := ConfigureResultJSON(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify empty fields with omitempty are not present
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if _, ok := raw["ssh_agent_socket_path"]; ok {
		t.Error("expected ssh_agent_socket_path to be omitted when empty")
	}
	if _, ok := raw["timezone"]; ok {
		t.Error("expected timezone to be omitted when empty")
	}
	if _, ok := raw["network_applied"]; ok {
		t.Error("expected network_applied to be omitted when empty")
	}
	if _, ok := raw["home_dir"]; !ok {
		t.Error("expected home_dir to always be present")
	}
}

func TestConfigureOptions_DefaultLogger(t *testing.T) {
	// Verify that a nil logger doesn't cause a panic
	opts := ConfigureOptions{
		ContainerName: "nonexistent-container-for-test",
	}

	// This will fail because the container doesn't exist, but it should
	// not panic due to nil logger
	_, err := ConfigureContainer(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error for nonexistent container")
	}
}

// Open mode also goes through SetupForContainer, before any exec into the
// container, and the caller gets the network manager to tear it down.
func TestConfigureContainer_NetworkFirstInEveryMode(t *testing.T) {
	network.SetSudoAllowed(false)
	t.Cleanup(func() { network.SetSudoAllowed(true) })
	const name = "cfg-net-first"
	logPath := fakeLimitsIncusStatus(t, name, "config: {}\ndevices: {}\n", "RUNNING")

	result, err := ConfigureContainer(context.Background(), ConfigureOptions{
		ContainerName: name,
		NetworkConfig: &config.NetworkConfig{Mode: config.NetworkModeOpen},
		Logger:        func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.NetworkApplied != string(config.NetworkModeOpen) || result.NetworkManager == nil {
		t.Errorf("NetworkApplied = %q, NetworkManager = %v; want open and a manager", result.NetworkApplied, result.NetworkManager)
	}

	b, _ := os.ReadFile(logPath)
	calls := strings.Split(strings.TrimSpace(string(b)), "\n")
	firstNet, firstExec := -1, -1
	for i, c := range calls {
		if firstNet == -1 && strings.Contains(c, "query /1.0/instances/"+name) {
			firstNet = i
		}
		if firstExec == -1 && strings.Contains(c, "exec ") {
			firstExec = i
		}
	}
	if firstNet == -1 || firstExec == -1 || firstNet > firstExec {
		t.Errorf("network lookup (call %d) must come before the first exec (call %d):\n%s", firstNet, firstExec, b)
	}
}
