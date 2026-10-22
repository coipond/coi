"""
Test for coi snapshot restore/delete - answering "n" to the confirmation.

Tests that:
1. Declining snapshot restore prints "Aborted" and does not restore
2. Declining snapshot delete --all prints "Aborted" and deletes no snapshot
"""

import subprocess

from support.helpers import (
    calculate_container_name,
    wait_for_container_started,
    wait_for_container_stopped,
)


def test_snapshot_restore_decline(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi snapshot restore' does not restore.

    Flow:
    1. Launch a container and create a snapshot
    2. Create a file after the snapshot, then stop the container
    3. Run coi snapshot restore without --force and answer "n"
    4. Verify "Aborted"
    5. Start the container and verify the file is still there
    6. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)
    snapshot_name = "decline-restore"
    marker = "/root/after-snapshot.txt"

    # === Phase 1: Launch container and create a snapshot ===
    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    result = subprocess.run(
        [coi_binary, "snapshot", "create", snapshot_name, "-c", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Snapshot create should succeed. stderr: {result.stderr}"

    # === Phase 2: Change the container after the snapshot, then stop it ===
    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "touch", marker],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Creating file should succeed. stderr: {result.stderr}"

    result = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container stop should succeed. stderr: {result.stderr}"
    stopped, last = wait_for_container_stopped(coi_binary, container_name)
    assert stopped, f"Container should stop. last: {last}"

    # === Phase 3: Decline ===
    result = subprocess.run(
        [coi_binary, "snapshot", "restore", snapshot_name, "-c", container_name],
        input="n\n",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Declined restore should exit 0. stderr: {result.stderr}"
    assert "Aborted" in result.stderr, f"Should report the abort. stderr:\n{result.stderr}"
    assert "Restored container" not in result.stderr, (
        f"Should restore nothing. stderr:\n{result.stderr}"
    )

    # === Phase 4: The change made after the snapshot is still there ===
    result = subprocess.run(
        [coi_binary, "container", "start", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container start should succeed. stderr: {result.stderr}"
    assert wait_for_container_started(coi_binary, container_name), "Container should start"

    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "test", "-f", marker],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"{marker} should survive a declined restore"

    # === Cleanup ===
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )


def test_snapshot_delete_all_decline(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi snapshot delete --all' deletes no snapshot.

    Flow:
    1. Launch a container and create two snapshots
    2. Run coi snapshot delete --all without --force and answer "n"
    3. Verify "Aborted" and that both snapshots still exist
    4. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)
    snapshots = ("decline-one", "decline-two")

    # === Phase 1: Launch container and create two snapshots ===
    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    for snapshot_name in snapshots:
        result = subprocess.run(
            [coi_binary, "snapshot", "create", snapshot_name, "-c", container_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, f"Snapshot create should succeed. stderr: {result.stderr}"

    # === Phase 2: Decline ===
    result = subprocess.run(
        [coi_binary, "snapshot", "delete", "--all", "-c", container_name],
        input="n\n",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Declined delete should exit 0. stderr: {result.stderr}"
    assert "Aborted" in result.stderr, f"Should report the abort. stderr:\n{result.stderr}"

    # === Phase 3: Both snapshots are still there ===
    result = subprocess.run(
        [coi_binary, "snapshot", "list", "-c", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Snapshot list should succeed. stderr: {result.stderr}"
    for snapshot_name in snapshots:
        assert snapshot_name in result.stdout, (
            f"Snapshot {snapshot_name} should survive. list:\n{result.stdout}"
        )

    # === Cleanup ===
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
