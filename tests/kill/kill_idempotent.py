"""
Test for coi kill - killing same container twice.

Tests that:
1. Launch a container
2. Kill it
3. Try to kill again
4. Verify the second kill exits non-zero with a message
"""

import subprocess
import time

from support.helpers import calculate_container_name


def test_kill_idempotent(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that killing a container twice fails on the second kill.

    Flow:
    1. Launch a container
    2. Kill it
    3. Try to kill again
    4. Verify second kill exits non-zero with a message
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container ===

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    # === Phase 2: First kill ===

    result = subprocess.run(
        [coi_binary, "kill", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"First kill should succeed. stderr: {result.stderr}"

    # === Phase 3: Second kill (container no longer exists) ===

    result = subprocess.run(
        [coi_binary, "kill", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )

    combined_output = result.stdout + result.stderr

    assert result.returncode != 0, (
        f"Second kill of a deleted container should fail. Got:\n{combined_output}"
    )
    assert (
        "failed" in combined_output.lower()
        or "warning" in combined_output.lower()
        or "not exist" in combined_output.lower()
        or "No containers" in combined_output
    ), f"Should show appropriate message. Got:\n{combined_output}"
