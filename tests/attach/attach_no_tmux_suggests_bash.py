"""
Test for coi attach - suggests --bash when no tmux session.

Tests that:
1. Start a container directly (without tmux session)
2. Run coi attach
3. Verify it suggests using --bash
"""

import subprocess
import time

from support.helpers import (
    calculate_container_name,
    get_container_list,
)


def test_attach_no_tmux_suggests_bash(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that coi attach suggests --bash when tmux session is gone.

    Flow:
    1. Launch a container directly (no tmux)
    2. Run coi attach
    3. Verify it suggests using --bash
    4. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container directly without tmux ===

    # Launch container using low-level command
    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    # Verify container is running
    containers = get_container_list()
    assert container_name in containers, f"Container {container_name} should be running"

    # === Phase 2: Try to attach (no tmux session exists) ===

    result = subprocess.run(
        [coi_binary, "attach", container_name],
        capture_output=True,
        text=True,
        timeout=10,
    )

    # Check output suggests using --bash
    combined_output = result.stdout + result.stderr
    # Failed tmux attach: exit code 1 (generic failure)
    assert result.returncode == 1, f"Failed attach should exit 1. Got:\n{combined_output}"
    assert "--bash" in combined_output or "No tmux session" in combined_output, (
        f"Should suggest using --bash. Got:\n{combined_output}"
    )

    # === Phase 3: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )

    time.sleep(1)
    containers = get_container_list()
    assert container_name not in containers, (
        f"Container {container_name} should be deleted after cleanup"
    )
