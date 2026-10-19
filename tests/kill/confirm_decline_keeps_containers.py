"""
Test that answering "n" to a confirmation prompt changes nothing.

Each test runs a command without --force, answers "n" on stdin, and checks
that the command reports the cancel ("Cancelled." or "Aborted") and leaves
the containers or snapshots as they were.
"""

import subprocess

from support.helpers import (
    calculate_container_name,
    wait_for_container_started,
    wait_for_container_stopped,
)


def _launch(coi_binary, container_name):
    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"


def _stop(coi_binary, container_name):
    result = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container stop should succeed. stderr: {result.stderr}"
    stopped, last = wait_for_container_stopped(coi_binary, container_name)
    assert stopped, f"Container should stop. last: {last}"


def _decline(coi_binary, argv):
    return subprocess.run(
        [coi_binary, *argv],
        input="n\n",
        capture_output=True,
        text=True,
        timeout=60,
    )


def _assert_exists(coi_binary, container_name):
    result = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Container {container_name} should still exist"


def _snapshots(coi_binary, container_name):
    result = subprocess.run(
        [coi_binary, "snapshot", "list", "-c", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Snapshot list should succeed. stderr: {result.stderr}"
    return result.stdout


def _create_snapshot(coi_binary, container_name, snapshot_name):
    result = subprocess.run(
        [coi_binary, "snapshot", "create", snapshot_name, "-c", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Snapshot create should succeed. stderr: {result.stderr}"


def _delete(coi_binary, *container_names):
    for name in container_names:
        subprocess.run(
            [coi_binary, "container", "delete", name, "--force"],
            capture_output=True,
            timeout=30,
        )


def test_kill_all_decline_keeps_containers(coi_binary, cleanup_containers, workspace_dir):
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
    _launch(coi_binary, container_name)

    # === Phase 2: Decline ===
    result = _decline(coi_binary, ["kill", "--all"])
    assert result.returncode == 0, f"Declined kill should exit 0. stderr: {result.stderr}"
    assert "Cancelled." in result.stdout, f"Should report the cancel. stdout:\n{result.stdout}"
    assert "Killing container" not in result.stdout, (
        f"Should kill nothing. stdout:\n{result.stdout}"
    )

    # === Phase 3: Verify ===
    _assert_exists(coi_binary, container_name)

    # === Cleanup ===
    _delete(coi_binary, container_name)


def test_shutdown_multiple_decline_keeps_containers(coi_binary, cleanup_containers, workspace_dir):
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
    for name in (container1, container2):
        _launch(coi_binary, name)

    # === Phase 2: Decline ===
    result = _decline(coi_binary, ["shutdown", container1, container2])
    assert result.returncode == 0, f"Declined shutdown should exit 0. stderr: {result.stderr}"
    assert "Cancelled." in result.stdout, f"Should report the cancel. stdout:\n{result.stdout}"
    assert "Shutting down container" not in result.stdout, (
        f"Should shut down nothing. stdout:\n{result.stdout}"
    )

    # === Phase 3: Verify ===
    for name in (container1, container2):
        _assert_exists(coi_binary, name)

    # === Cleanup ===
    _delete(coi_binary, container1, container2)


def test_persist_all_decline_persists_nothing(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi persist --all' persists nothing.

    Flow:
    1. Launch a container
    2. Run coi persist --all and answer "n"
    3. Verify "Cancelled." and that no container was persisted
    4. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container ===
    _launch(coi_binary, container_name)

    # === Phase 2: Decline ===
    result = _decline(coi_binary, ["persist", "--all"])
    assert result.returncode == 0, f"Declined persist should exit 0. stderr: {result.stderr}"
    assert "Cancelled." in result.stdout, f"Should report the cancel. stdout:\n{result.stdout}"
    assert "Persisting container" not in result.stdout, (
        f"Should persist nothing. stdout:\n{result.stdout}"
    )

    # === Phase 3: Verify ===
    _assert_exists(coi_binary, container_name)

    # === Cleanup ===
    _delete(coi_binary, container_name)


def test_clean_decline_keeps_stopped_container(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi clean' deletes no stopped container.

    Flow:
    1. Launch a container and stop it
    2. Run coi clean and answer "n"
    3. Verify "Cancelled." and that the stopped container still exists
    4. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch and stop container ===
    _launch(coi_binary, container_name)
    _stop(coi_binary, container_name)

    # === Phase 2: Decline ===
    result = _decline(coi_binary, ["clean"])
    assert result.returncode == 0, f"Declined clean should exit 0. stderr: {result.stderr}"
    assert f"  - {container_name}" in result.stdout, (
        f"Should list the stopped container. stdout:\n{result.stdout}"
    )
    assert "Cancelled." in result.stdout, f"Should report the cancel. stdout:\n{result.stdout}"
    assert "Deleting container" not in result.stdout, (
        f"Should delete nothing. stdout:\n{result.stdout}"
    )

    # === Phase 3: Verify ===
    _assert_exists(coi_binary, container_name)

    # === Cleanup ===
    _delete(coi_binary, container_name)


def test_snapshot_restore_decline_keeps_changes(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi snapshot restore' does not restore.

    Flow:
    1. Launch a container and create a snapshot
    2. Create a file after the snapshot, then stop the container
    3. Run coi snapshot restore and answer "n"
    4. Verify "Aborted"
    5. Start the container and verify the file is still there
    6. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)
    snapshot_name = "decline-restore"
    marker = "/root/after-snapshot.txt"

    # === Phase 1: Launch container and snapshot it ===
    _launch(coi_binary, container_name)
    _create_snapshot(coi_binary, container_name, snapshot_name)

    # === Phase 2: Change the container after the snapshot, then stop it ===
    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "touch", marker],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Creating file should succeed. stderr: {result.stderr}"
    _stop(coi_binary, container_name)

    # === Phase 3: Decline ===
    result = _decline(coi_binary, ["snapshot", "restore", snapshot_name, "-c", container_name])
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
    _delete(coi_binary, container_name)


def test_snapshot_delete_all_decline_keeps_snapshots(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that declining 'coi snapshot delete --all' deletes no snapshot.

    Flow:
    1. Launch a container and create two snapshots
    2. Run coi snapshot delete --all and answer "n"
    3. Verify "Aborted" and that both snapshots still exist
    4. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)
    snapshots = ("decline-one", "decline-two")

    # === Phase 1: Launch container and snapshot it twice ===
    _launch(coi_binary, container_name)
    for name in snapshots:
        _create_snapshot(coi_binary, container_name, name)

    # === Phase 2: Decline ===
    result = _decline(coi_binary, ["snapshot", "delete", "--all", "-c", container_name])
    assert result.returncode == 0, f"Declined delete should exit 0. stderr: {result.stderr}"
    assert "Aborted" in result.stderr, f"Should report the abort. stderr:\n{result.stderr}"

    # === Phase 3: Verify ===
    listing = _snapshots(coi_binary, container_name)
    for name in snapshots:
        assert name in listing, f"Snapshot {name} should survive. list:\n{listing}"

    # === Cleanup ===
    _delete(coi_binary, container_name)
