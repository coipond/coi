//go:build integration

package session

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/container"
)

// skipUnlessSSHAgentTestable skips the test if prerequisites are missing.
func skipUnlessSSHAgentTestable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}
}

// skipUnlessSSHToolsAvailable additionally checks for SSH tools.
func skipUnlessSSHToolsAvailable(t *testing.T) {
	t.Helper()
	skipUnlessSSHAgentTestable(t)
	for _, tool := range []string{"ssh-keygen", "ssh-agent", "ssh-add"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found, skipping integration test", tool)
		}
	}
}

// startTestAgent creates a temp SSH key, starts ssh-agent, loads the key, and
// returns the agent socket path. The agent is killed in t.Cleanup.
func startTestAgent(t *testing.T, keyComment string) string {
	t.Helper()

	keyDir := t.TempDir()
	keyPath := keyDir + "/test_key"

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", keyComment)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to generate SSH key: %v\n%s", err, out)
	}

	agentOut, err := exec.Command("ssh-agent", "-s").Output()
	if err != nil {
		t.Fatalf("Failed to start ssh-agent: %v", err)
	}

	agentSocket, agentPID := parseAgentOutput(t, string(agentOut))
	t.Logf("Started ssh-agent: socket=%s pid=%s", agentSocket, agentPID)

	t.Cleanup(func() {
		_ = exec.Command("kill", agentPID).Run()
	})

	addCmd := exec.Command("ssh-add", keyPath)
	addCmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket)
	if out, err := addCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to add key to agent: %v\n%s", err, out)
	}

	return agentSocket
}

// launchTestContainer creates and starts a container, registering cleanup.
func launchTestContainer(t *testing.T, name string) *container.Manager {
	t.Helper()
	mgr := container.NewManager(name)

	t.Cleanup(func() {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	})

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("Failed to launch container: %v", err)
	}

	// Wait for container to be ready
	for i := 0; i < 30; i++ {
		if _, err := mgr.ExecCommand("echo ready", container.ExecCommandOptions{Capture: true}); err == nil {
			return mgr
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("Container failed to become ready")
	return nil
}

// TestSSHAgentForwarding_EndToEnd verifies that a host SSH agent socket is
// forwarded into the container via an Incus proxy device, and that ssh-add
// inside the container can see the loaded key.
func TestSSHAgentForwarding_EndToEnd(t *testing.T) {
	skipUnlessSSHToolsAvailable(t)

	// 1. Start agent with test key
	agentSocket := startTestAgent(t, "coi-integration-test")

	// Verify key is loaded on host
	listCmd := exec.Command("ssh-add", "-l")
	listCmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket)
	hostListOut, err := listCmd.Output()
	if err != nil {
		t.Fatalf("Failed to list keys on host: %v", err)
	}
	hostKeys := strings.TrimSpace(string(hostListOut))
	t.Logf("Host ssh-add -l: %s", hostKeys)
	hostFingerprint := extractFingerprint(t, hostKeys)

	// 2. Launch running container
	containerName := "coi-test-ssh-agent"
	mgr := launchTestContainer(t, containerName)

	// 3. Setup SSH agent forwarding on the RUNNING container
	// Proxy devices must be added to running containers to work
	t.Setenv("SSH_AUTH_SOCK", agentSocket)
	logger := func(msg string) { t.Logf("[ssh-agent] %s", msg) }
	socketPath, err := SetupSSHAgentForwarding(mgr, containerName, logger)
	if err != nil {
		t.Fatalf("SetupSSHAgentForwarding failed: %v", err)
	}
	if socketPath == "" {
		t.Fatal("SetupSSHAgentForwarding returned empty socket path, expected forwarding to be configured")
	}

	// 4. Wait for socket to appear (proxy device may take a moment)
	user := container.CodeUID
	for i := 0; i < 10; i++ {
		out, err := mgr.ExecCommand("test -S /tmp/ssh-agent.sock && echo ok", container.ExecCommandOptions{Capture: true})
		if err == nil && strings.TrimSpace(out) == "ok" {
			break
		}
		if i == 9 {
			debugOut, _ := mgr.ExecCommand("ls -la /tmp/ 2>&1", container.ExecCommandOptions{Capture: true})
			devOut, _ := container.IncusOutput("config", "device", "show", containerName)
			t.Fatalf("SSH agent socket never appeared (devices: %s, /tmp: %s)", devOut, debugOut)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// 5. Verify ssh-add -l works inside the container
	containerOut, err := mgr.ExecCommand("ssh-add -l", container.ExecCommandOptions{
		Capture: true,
		User:    &user,
		Env:     map[string]string{"SSH_AUTH_SOCK": "/tmp/ssh-agent.sock"},
	})
	if err != nil {
		t.Fatalf("ssh-add -l inside container failed: %v (output: %q)", err, containerOut)
	}

	containerKeys := strings.TrimSpace(containerOut)
	t.Logf("Container ssh-add -l: %s", containerKeys)

	if !strings.Contains(containerKeys, "coi-integration-test") {
		t.Errorf("Expected key comment 'coi-integration-test' in container, got: %s", containerKeys)
	}

	containerFingerprint := extractFingerprint(t, containerKeys)
	if hostFingerprint != containerFingerprint {
		t.Errorf("Key fingerprint mismatch: host=%s container=%s", hostFingerprint, containerFingerprint)
	}
}

// TestSSHAgentForwarding_NoSocket verifies that forwarding is gracefully skipped
// when SSH_AUTH_SOCK is not set.
func TestSSHAgentForwarding_NoSocket(t *testing.T) {
	skipUnlessSSHAgentTestable(t)

	containerName := "coi-test-ssh-agent-nosock"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	})

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	// Only need init (not start) since we're testing that forwarding is skipped
	if err := container.IncusExec("init", "coi-default", containerName); err != nil {
		t.Fatalf("Failed to init container: %v", err)
	}

	t.Setenv("SSH_AUTH_SOCK", "")

	var logMessages []string
	logger := func(msg string) {
		logMessages = append(logMessages, msg)
		t.Logf("[ssh-agent] %s", msg)
	}

	socketPath, err := SetupSSHAgentForwarding(mgr, containerName, logger)
	if err != nil {
		t.Errorf("Expected no error when SSH_AUTH_SOCK is empty, got: %v", err)
	}
	if socketPath != "" {
		t.Errorf("Expected empty socket path when SSH_AUTH_SOCK is empty, got: %s", socketPath)
	}

	found := false
	for _, msg := range logMessages {
		if strings.Contains(msg, "SSH_AUTH_SOCK not set") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected skip message about SSH_AUTH_SOCK, got: %v", logMessages)
	}
}

// TestSSHAgentForwarding_InvalidSocket verifies that forwarding is gracefully
// skipped when SSH_AUTH_SOCK points to a non-existent path.
func TestSSHAgentForwarding_InvalidSocket(t *testing.T) {
	skipUnlessSSHAgentTestable(t)

	containerName := "coi-test-ssh-agent-badsock"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	})

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	// Only need init (not start) since we're testing that forwarding is skipped
	if err := container.IncusExec("init", "coi-default", containerName); err != nil {
		t.Fatalf("Failed to init container: %v", err)
	}

	t.Setenv("SSH_AUTH_SOCK", "/tmp/nonexistent-ssh-agent-socket-12345")

	var logMessages []string
	logger := func(msg string) {
		logMessages = append(logMessages, msg)
		t.Logf("[ssh-agent] %s", msg)
	}

	socketPath, err := SetupSSHAgentForwarding(mgr, containerName, logger)
	if err != nil {
		t.Errorf("Expected no error when socket doesn't exist, got: %v", err)
	}
	if socketPath != "" {
		t.Errorf("Expected empty socket path when socket doesn't exist, got: %s", socketPath)
	}

	found := false
	for _, msg := range logMessages {
		if strings.Contains(msg, "not accessible") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected skip message about socket not accessible, got: %v", logMessages)
	}
}

// TestSSHAgentForwarding_DeviceReplace verifies that calling SetupSSHAgentForwarding
// twice on a running container (e.g., persistent container with changed socket path)
// replaces the proxy device cleanly.
func TestSSHAgentForwarding_DeviceReplace(t *testing.T) {
	skipUnlessSSHToolsAvailable(t)

	agentSocket := startTestAgent(t, "coi-replace-test")

	// Launch running container
	containerName := "coi-test-ssh-agent-replace"
	mgr := launchTestContainer(t, containerName)

	t.Setenv("SSH_AUTH_SOCK", agentSocket)
	logger := func(msg string) { t.Logf("[ssh-agent] %s", msg) }

	// First call - add device to running container
	if _, err := SetupSSHAgentForwarding(mgr, containerName, logger); err != nil {
		t.Fatalf("First SetupSSHAgentForwarding failed: %v", err)
	}

	// Second call - should remove and re-add device without error
	if _, err := SetupSSHAgentForwarding(mgr, containerName, logger); err != nil {
		t.Fatalf("Second SetupSSHAgentForwarding failed: %v", err)
	}

	// Wait for socket
	for i := 0; i < 10; i++ {
		out, err := mgr.ExecCommand("test -S /tmp/ssh-agent.sock && echo ok", container.ExecCommandOptions{Capture: true})
		if err == nil && strings.TrimSpace(out) == "ok" {
			break
		}
		if i == 9 {
			t.Fatal("SSH agent socket never appeared after device replacement")
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Verify it works
	user := container.CodeUID
	containerOut, err := mgr.ExecCommand("ssh-add -l", container.ExecCommandOptions{
		Capture: true,
		User:    &user,
		Env:     map[string]string{"SSH_AUTH_SOCK": "/tmp/ssh-agent.sock"},
	})
	if err != nil {
		t.Fatalf("ssh-add -l inside container failed after device replacement: %v (output: %s)", err, containerOut)
	}

	if !strings.Contains(containerOut, "coi-replace-test") {
		t.Errorf("Expected key 'coi-replace-test' in container, got: %s", containerOut)
	}
}

// parseAgentOutput extracts SSH_AUTH_SOCK and SSH_AGENT_PID from ssh-agent -s output.
func parseAgentOutput(t *testing.T, output string) (socket, pid string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSH_AUTH_SOCK=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				socket = strings.TrimSuffix(parts[1], "; export SSH_AUTH_SOCK;")
				socket = strings.TrimRight(socket, ";")
				socket = strings.TrimSpace(socket)
			}
		}
		if strings.HasPrefix(line, "SSH_AGENT_PID=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				pid = strings.TrimSuffix(parts[1], "; export SSH_AGENT_PID;")
				pid = strings.TrimRight(pid, ";")
				pid = strings.TrimSpace(pid)
			}
		}
	}
	if socket == "" {
		t.Fatalf("Failed to parse SSH_AUTH_SOCK from agent output:\n%s", output)
	}
	if pid == "" {
		t.Fatalf("Failed to parse SSH_AGENT_PID from agent output:\n%s", output)
	}
	return socket, pid
}

// extractFingerprint extracts the key fingerprint (SHA256:...) from ssh-add -l output.
func extractFingerprint(t *testing.T, sshAddOutput string) string {
	t.Helper()
	for _, line := range strings.Split(sshAddOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "SHA256:") {
			return fields[1]
		}
	}
	t.Fatalf("No SHA256 fingerprint found in ssh-add output: %s", sshAddOutput)
	return ""
}
