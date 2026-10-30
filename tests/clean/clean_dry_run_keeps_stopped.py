"""
Test for coi clean --dry-run - lists stopped containers but deletes nothing.

Tests that:
1. Launch a container and stop it
2. Run coi clean --dry-run
3. Verify the container is listed and "[Dry run] No changes made." is printed
4. Verify the container still exists
"""

import subprocess

from support.helpers import calculate_container_name, wait_for_container_stopped


def test_clean_dry_run_keeps_stopped(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that 'coi clean --dry-run' lists a stopped container and keeps it.

    Flow:
    1. Launch a container and stop it
    2. Run coi clean --dry-run
    3. Verify the container is listed and the dry-run line is printed
    4. Verify the container still exists
    5. Cleanup
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

    # === Phase 2: Dry run ===
    result = subprocess.run(
        [coi_binary, "clean", "--dry-run"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"coi clean --dry-run should succeed. stderr: {result.stderr}"
    assert f"  - {container_name}" in result.stdout, (
        f"Dry run should list the stopped container. stdout:\n{result.stdout}"
    )
    assert "[Dry run] No changes made." in result.stdout, (
        f"Dry run should say nothing changed. stdout:\n{result.stdout}"
    )
    assert "Deleting container" not in result.stdout, (
        f"Dry run should not delete anything. stdout:\n{result.stdout}"
    )

    # === Phase 3: Container is still there ===
    result = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Container {container_name} should survive a dry run"

    # === Cleanup ===
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
