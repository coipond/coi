"""Test HIGH-level threats that trigger auto-pause."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    container_io_stat,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
    wait_for_frozen,
)


def test_large_file_read_triggers_auto_pause(
    test_workspace, enable_monitoring_low_thresholds, coi_binary
):
    """Test large file read detection (HIGH) triggers auto-pause."""
    # Create a 200MB binary file (well above the 50MB threshold).
    # Using a binary file with write_bytes and direct dd (same pattern as the
    # reliably passing test_file_read_above_threshold_triggers) to ensure
    # O_DIRECT succeeds and block I/O is counted by the cgroup monitor.
    large_file = Path(test_workspace) / "secrets.bin"
    large_file.write_bytes(b"S" * (200 * 1024 * 1024))

    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "6"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-6"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Wait for monitoring to establish stable baseline
    time.sleep(10)

    # Read the 200MB file directly with dd and O_DIRECT to bypass page cache.
    # Running dd directly (not via a python wrapper) matches the reliable pattern
    # used in test_file_read_above_threshold_triggers which consistently passes.
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "dd",
            "if=/workspace/secrets.bin",
            "of=/dev/null",
            "bs=1M",
            "iflag=direct",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    paused = wait_for_frozen(container_name)

    if not paused:
        events = get_threat_events(container_name)
        print("\n=== DEBUG: large file read test - container not paused ===")
        print(f"Final state: {get_container_state(container_name)}")
        print(f"Total threat events: {len(events)}")
        for event in events:
            print(
                f"- level={event.get('level')}, category={event.get('category')}, "
                f"action={event.get('action')}, desc={event.get('description')[:80] if event.get('description') else 'N/A'}"
            )
        print("=== END DEBUG ===\n")

    proc.terminate()

    assert paused, (
        "Container should be auto-paused on HIGH threat (large file read)"
        + container_io_stat(container_name)
    )

    # Verify HIGH threat in audit log
    events = get_threat_events(container_name)
    high_threats = [e for e in events if e.get("level") == "high"]
    assert len(high_threats) > 0, "Expected HIGH threat event for large file read"

    # Verify action was "paused"
    paused_events = [e for e in events if e.get("action") == "paused"]
    assert len(paused_events) > 0, "Expected action='paused' in audit log"

    cleanup_container(container_name, coi_binary)
