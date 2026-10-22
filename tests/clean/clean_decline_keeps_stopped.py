"""
Test for coi clean - answering "n" to the confirmation deletes nothing.

Tests that:
1. Launch a container and stop it
2. Run coi clean without --force and answer "n"
3. Verify "Cancelled." is printed and the stopped container still exists
"""

import subprocess

from support.helpers import calculate_container_name, wait_for_container_stopped


def test_clean_decline_keeps_stopped(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi clean' deletes no stopped container.

    Flow:
    1. Launch a container and stop it
    2. Run coi clean and answer "n"
    3. Verify "Cancelled." and that the stopped container still exists
    4. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch and stop a container ===
    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    result = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container stop should succeed. stderr: {result.stderr}"
    stopped, last = wait_for_container_stopped(coi_binary, container_name)
    assert stopped, f"Container should stop. last: {last}"

    # === Phase 2: Decline ===
    result = subprocess.run(
        [coi_binary, "clean"],
        input="n\n",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Declined clean should exit 0. stderr: {result.stderr}"
    assert f"  - {container_name}" in result.stdout, (
        f"Should list the stopped container. stdout:\n{result.stdout}"
    )
    assert "Cancelled." in result.stdout, f"Should report the cancel. stdout:\n{result.stdout}"
    assert "Deleting container" not in result.stdout, (
        f"Should delete nothing. stdout:\n{result.stdout}"
    )

    # === Phase 3: Container is still there ===
    result = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Container {container_name} should survive a declined clean"

    # === Cleanup ===
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
