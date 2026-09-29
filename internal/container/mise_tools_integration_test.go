//go:build integration

package container

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestMiseTools_AvailableInImage verifies that mise-managed tools (python3, pnpm,
// tsc, tsx) are installed and accessible in the Coi container image via mise.
func TestMiseTools_AvailableInImage(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}
	exists, err := ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	containerName := "coi-test-mise-tools"
	mgr := NewManager(containerName)

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
		if _, err := mgr.ExecCommand("echo ready", ExecCommandOptions{Capture: true}); err == nil {
			break
		}
		if i == 29 {
			t.Fatal("Container failed to become ready")
		}
		time.Sleep(1 * time.Second)
	}

	user := CodeUID

	// Verify mise itself is installed
	t.Run("mise_installed", func(t *testing.T) {
		out, err := mgr.ExecCommand("mise --version", ExecCommandOptions{
			Capture: true,
			User:    &user,
		})
		if err != nil {
			t.Fatalf("mise not available: %v", err)
		}
		t.Logf("mise version: %s", strings.TrimSpace(out))
	})

	// Verify mise activation is in .bashrc
	t.Run("mise_activated_in_bashrc", func(t *testing.T) {
		out, err := mgr.ExecCommand("grep 'mise activate' /home/code/.bashrc", ExecCommandOptions{
			Capture: true,
			User:    &user,
		})
		if err != nil {
			t.Fatalf("mise activation not found in .bashrc: %v", err)
		}
		if !strings.Contains(out, "mise activate bash") {
			t.Error("Expected 'mise activate bash' in .bashrc")
		}
	})

	// Verify mise activation is in .profile
	t.Run("mise_activated_in_profile", func(t *testing.T) {
		out, err := mgr.ExecCommand("grep 'mise activate' /home/code/.profile", ExecCommandOptions{
			Capture: true,
			User:    &user,
		})
		if err != nil {
			t.Fatalf("mise activation not found in .profile: %v", err)
		}
		if !strings.Contains(out, "mise activate bash") {
			t.Error("Expected 'mise activate bash' in .profile")
		}
	})

	// Verify system-wide mise activation in /etc/profile.d
	t.Run("mise_activated_system_wide", func(t *testing.T) {
		out, err := mgr.ExecCommand("cat /etc/profile.d/mise.sh", ExecCommandOptions{
			Capture: true,
			User:    &user,
		})
		if err != nil {
			t.Fatalf("/etc/profile.d/mise.sh not found: %v", err)
		}
		if !strings.Contains(out, "mise activate bash") {
			t.Error("Expected 'mise activate bash' in /etc/profile.d/mise.sh")
		}
	})

	// Verify each mise-managed tool is accessible via `mise exec`
	tools := []struct {
		name    string
		command string
		expect  string // substring expected in output
	}{
		{"python3", "mise exec -- python3 --version", "Python 3"},
		{"pip", "mise exec -- pip --version", "pip"},
		{"pnpm", "mise exec -- pnpm --version", "."},
		{"tsc", "mise exec -- tsc --version", "."},
		{"tsx", "mise exec -- tsx --version", "."},
	}

	for _, tc := range tools {
		t.Run(tc.name, func(t *testing.T) {
			out, err := mgr.ExecCommand(tc.command, ExecCommandOptions{
				Capture: true,
				User:    &user,
			})
			if err != nil {
				t.Fatalf("%s not available via mise: %v (output: %s)", tc.name, err, out)
			}
			if !strings.Contains(out, tc.expect) {
				t.Errorf("Expected %q in output, got: %s", tc.expect, strings.TrimSpace(out))
			}
			t.Logf("%s: %s", tc.name, strings.TrimSpace(out))
		})
	}

	// Verify Python venv works (mise-managed Python should include venv)
	t.Run("python_venv", func(t *testing.T) {
		_, err := mgr.ExecCommand(
			"mise exec -- python3 -m venv /tmp/test-venv && /tmp/test-venv/bin/python --version",
			ExecCommandOptions{
				Capture: true,
				User:    &user,
			},
		)
		if err != nil {
			t.Fatalf("Python venv creation failed: %v", err)
		}
	})

	// Verify system Node.js is still available (not replaced by mise)
	t.Run("system_nodejs", func(t *testing.T) {
		out, err := mgr.ExecCommand("node --version", ExecCommandOptions{
			Capture: true,
			User:    &user,
		})
		if err != nil {
			t.Fatalf("System Node.js not available: %v", err)
		}
		if !strings.HasPrefix(strings.TrimSpace(out), "v") {
			t.Errorf("Expected Node.js version starting with 'v', got: %s", out)
		}
		t.Logf("System Node.js: %s", strings.TrimSpace(out))
	})
}
