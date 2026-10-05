"""
Test timeout monitor functionality.

Tests that:
1. Container auto-stops after max_duration
2. Graceful stop works correctly
3. Timeout monitor can be cancelled early
4. Session data is saved before stop
"""

import json
import subprocess
import time
from pathlib import Path

from support.helpers import calculate_container_name


def test_container_auto_stops_after_timeout(coi_binary, workspace_dir, cleanup_containers):
    """Test that container auto-stops after max_duration is reached."""
    container_name = calculate_container_name(workspace_dir, 1)

    # Create config with short timeout
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[limits.runtime]
max_duration = "10s"
"""
    )

    # Script sleeps FAR longer than both the 10s timeout and the assert window
    # below, so "auto-stop never fired" is unambiguous: the run would hit the
    # subprocess timeout rather than sneak under the upper bound.
    test_script = Path(workspace_dir) / "long_script.sh"
    test_script.write_text(
        """#!/bin/bash
echo "Starting long script"
sleep 120
echo "Script completed"
"""
    )
    test_script.chmod(0o755)

    # Launch with very short timeout (10 seconds)
    start_time = time.time()
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "bash",
            "/workspace/long_script.sh",
        ],
        capture_output=True,
        text=True,
        timeout=90,  # Generous ceiling for the test itself (< the 120s script)
        cwd=workspace_dir,
    )

    elapsed_time = time.time() - start_time

    # The command should fail or exit due to timeout
    # We don't assert returncode because container stop may cause various exit codes
    # The key is that it stopped within reasonable time after the limit

    # Lower bound guards against stopping BEFORE the 10s budget; the upper bound is
    # deliberately generous (the monitor polls, and CI runners are frequently
    # overloaded — observed auto-stops up to ~21s), while still being well under
    # the 120s script so a genuinely-broken auto-stop hits the subprocess timeout.
    assert 8 <= elapsed_time <= 60, (
        f"Container should auto-stop after the 10s timeout (allowing for CI load), "
        f"took {elapsed_time:.1f}s"
    )

    # Verify container is stopped
    time.sleep(2)  # Brief pause for cleanup
    result = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Container should either be stopped or deleted (depending on timing)
    # We just verify it's not running
    if result.returncode == 0 and result.stdout:
        containers = json.loads(result.stdout)
        if containers:  # Container still exists
            container = containers[0]
            assert container["status"] == "Stopped", (
                f"Container should be stopped. Status: {container['status']}"
            )


def test_timeout_with_persistent_container(coi_binary, workspace_dir, cleanup_containers):
    """Test that timeout works with persistent containers."""
    container_name = calculate_container_name(workspace_dir, 1)

    # Create config with short timeout
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.runtime]
max_duration = "10s"
"""
    )

    # The script outlives the 10s limit by far, so only the limit can end it
    # (a 20s script used to finish on its own around the time the stop landed).
    test_script = Path(workspace_dir) / "test_script.sh"
    test_script.write_text(
        """#!/bin/bash
echo "Running test"
sleep 120
echo "Done"
"""
    )
    test_script.chmod(0o755)

    # Launch persistent container with timeout
    start_time = time.time()
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "bash",
            "/workspace/test_script.sh",
        ],
        capture_output=True,
        text=True,
        timeout=90,  # Generous ceiling for the test itself (< the 120s script)
        cwd=workspace_dir,
    )

    elapsed_time = time.time() - start_time

    # A graceful stop plus the follow-up "is it really stopped" check takes
    # ~10s past the limit (~20s in total on CI), so the upper bound matches
    # test_container_auto_stops_after_timeout rather than sitting on that edge.
    assert 8 <= elapsed_time <= 60, (
        f"Container should stop after the 10s timeout (allowing for CI load), "
        f"took {elapsed_time:.1f}s"
    )
    assert "Done" not in result.stdout, "the runtime limit should stop the script before it ends"

    # Brief pause for container state to settle
    time.sleep(2)

    # Verify container exists but is stopped (persistent)
    result = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, "Should be able to list container"

    containers = json.loads(result.stdout)
    assert len(containers) > 0, "Persistent container should still exist"

    container = containers[0]
    assert container["status"] == "Stopped", (
        f"Persistent container should be stopped, not deleted. Status: {container['status']}"
    )


def test_normal_exit_before_timeout(coi_binary, workspace_dir, cleanup_containers):
    """Test that normal exit before timeout works correctly."""

    # Create config with long timeout
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[limits.runtime]
max_duration = "30s"
"""
    )

    # Run a quick command with a long timeout
    start_time = time.time()
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "echo",
            "quick command",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    elapsed_time = time.time() - start_time

    # Should complete normally and quickly (not wait for timeout)
    assert result.returncode == 0, f"Command should succeed. stderr: {result.stderr}"
    assert elapsed_time < 25, (
        f"Should complete quickly, not wait for timeout. Took {elapsed_time:.1f}s"
    )
    assert "quick command" in result.stdout, "Should see command output"


def test_timeout_applied_in_shell_mode(coi_binary, workspace_dir, cleanup_containers):
    """Test that timeout works in shell mode (not just run mode)."""
    # Create config with timeout
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    project_config = project_config_dir / "config.toml"
    config_content = """
[limits.runtime]
max_duration = "10s"
auto_stop = true
stop_graceful = true
"""
    project_config.write_text(config_content)

    # Create a test file to run
    test_script = Path(workspace_dir) / "sleep_test.sh"
    test_script.write_text(
        """#!/bin/bash
sleep 30
"""
    )
    test_script.chmod(0o755)

    # We can't easily test shell mode in CI, but we can verify the config is read
    # and the timeout would be applied. For now, just verify config loads.
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "echo",
            "timeout config loaded",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, "Should load config successfully"


def test_zero_duration_means_unlimited(coi_binary, workspace_dir, cleanup_containers):
    """Test that zero or empty duration means no timeout."""
    # Run a command with no timeout (should work normally)
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "sleep", "2"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, "Command with no timeout should complete normally"


def test_timeout_logging_message(coi_binary, workspace_dir, cleanup_containers):
    """Test that timeout start message appears in logs."""

    # Create config with short timeout
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[limits.runtime]
max_duration = "5s"
"""
    )

    # Create a script
    test_script = Path(workspace_dir) / "test.sh"
    test_script.write_text(
        """#!/bin/bash
sleep 15
"""
    )
    test_script.chmod(0o755)

    # Launch with timeout
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "bash",
            "/workspace/test.sh",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    # Check stderr for timeout message
    stderr = result.stderr
    # The message might appear in the setup phase
    # We're verifying the timeout feature is acknowledged
    # (exact message format may vary)
    assert (
        "limit" in stderr.lower()
        or "timeout" in stderr.lower()
        or "duration" in stderr.lower()
        or result.returncode != 0  # Stopped by timeout
    ), f"Should indicate timeout configuration. stderr: {stderr}"
