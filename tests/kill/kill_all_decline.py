"""
Test for coi kill --all - answering "n" to the confirmation kills nothing.

Tests that:
1. Launch a container
2. Run coi kill --all without --force and answer "n"
3. Verify "Cancelled." is printed and the container still exists
"""

import subprocess

from support.helpers import calculate_container_name


def test_kill_all_decline(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi kill --all' kills nothing.

    Flow:
    1. Launch a container
    2. Run coi kill --all and answer "n"
    3. Verify "Cancelled." and that the container still exists
    4. Cleanup
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

    # === Phase 2: Decline ===
    result = subprocess.run(
        [coi_binary, "kill", "--all"],
        input="n\n",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Declined kill should exit 0. stderr: {result.stderr}"
    assert "Cancelled." in result.stdout, f"Should report the cancel. stdout:\n{result.stdout}"
    assert "Killing container" not in result.stdout, (
        f"Should kill nothing. stdout:\n{result.stdout}"
    )

    # === Phase 3: Container is still there ===
    result = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Container {container_name} should survive a declined kill"

    # === Cleanup ===
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
