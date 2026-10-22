"""
Test for coi persist --all - answering "n" to the confirmation persists nothing.

Tests that:
1. Launch a container
2. Run coi persist --all without --force and answer "n"
3. Verify "Cancelled." is printed and no container is persisted
"""

import subprocess

from support.helpers import calculate_container_name


def test_persist_all_decline(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi persist --all' persists nothing.

    Flow:
    1. Launch a container
    2. Run coi persist --all and answer "n"
    3. Verify "Cancelled." and that no "Persisting container" line is printed
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
        [coi_binary, "persist", "--all"],
        input="n\n",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Declined persist should exit 0. stderr: {result.stderr}"
    assert "Cancelled." in result.stdout, f"Should report the cancel. stdout:\n{result.stdout}"
    assert "Persisting container" not in result.stdout, (
        f"Should persist nothing. stdout:\n{result.stdout}"
    )

    # === Cleanup ===
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
