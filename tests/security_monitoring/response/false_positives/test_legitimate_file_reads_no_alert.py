"""Test that legitimate commands don't trigger false alerts."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_legitimate_file_reads_no_alert(test_workspace, enable_monitoring, coi_binary):
    """Test that small file reads don't trigger false alerts."""
    # Create a small file (well below 50MB threshold)
    small_file = Path(test_workspace) / "data.txt"
    small_file.write_text("Some data\n" * 1000)  # ~10KB

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "23",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-23"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize (prevents startup I/O from affecting test)
    time.sleep(15)

    # Verify container is still running before the test
    pre_state = get_container_state(container_name)
    if pre_state != "Running":
        proc.terminate()
        events = get_threat_events(container_name)
        print("\n=== DEBUG: Container not running before file read ===")
        print(f"State: {pre_state}")
        print(f"Events: {events}")
        print("=== END DEBUG ===\n")
        cleanup_container(container_name, coi_binary)
        pytest.fail(f"Container stopped before file read test: {pre_state}")

    # Read the small file - should NOT trigger
    subprocess.run(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "cat",
            "/workspace/data.txt",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )

    # Wait to see if it would be detected
    time.sleep(5)

    # Container should still be running (no false positive)
    state = get_container_state(container_name)
    if state != "Running":
        events = get_threat_events(container_name)
        print("\n=== DEBUG: Container stopped after file read ===")
        print(f"State: {state}")
        print(f"Events: {len(events)} total")
        for e in events:
            print(f"  - {e.get('level')}: {e.get('title')} ({e.get('category')})")
        print("=== END DEBUG ===\n")

    assert state == "Running", f"Container should stay running on small file read, got {state}"

    # Check audit log - should have no HIGH threats for file reads
    events = get_threat_events(container_name)
    high_fs_threats = [
        e for e in events if e.get("level") == "high" and e.get("category") == "filesystem"
    ]
    assert len(high_fs_threats) == 0, "Small file read should not trigger HIGH threat"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
