"""
Test for coi shutdown - answering "n" when shutting down several containers.

Tests that:
1. Launch two containers
2. Run coi shutdown with both names, without --force, and answer "n"
3. Verify "Cancelled." is printed and both containers still exist
"""

import subprocess

from support.helpers import calculate_container_name


def test_shutdown_multiple_decline(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi shutdown <a> <b>' shuts down nothing.

    Flow:
    1. Launch two containers
    2. Run coi shutdown with both names and answer "n"
    3. Verify "Cancelled." and that both containers still exist
    4. Cleanup
    """
    container1 = calculate_container_name(workspace_dir, 1)
    container2 = calculate_container_name(workspace_dir, 2)

    # === Phase 1: Launch containers ===
    for container_name in (container1, container2):
        result = subprocess.run(
            [coi_binary, "container", "launch", "coi-default", container_name],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    # === Phase 2: Decline ===
    result = subprocess.run(
        [coi_binary, "shutdown", container1, container2],
        input="n\n",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Declined shutdown should exit 0. stderr: {result.stderr}"
    assert "Cancelled." in result.stdout, f"Should report the cancel. stdout:\n{result.stdout}"
    assert "Shutting down container" not in result.stdout, (
        f"Should shut down nothing. stdout:\n{result.stdout}"
    )

    # === Phase 3: Both containers are still there ===
    for container_name in (container1, container2):
        result = subprocess.run(
            [coi_binary, "container", "exists", container_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Container {container_name} should survive a declined shutdown"
        )

    # === Cleanup ===
    for container_name in (container1, container2):
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
