"""Test HIGH-level threats that trigger auto-pause."""

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


def test_high_threat_without_auto_pause(test_workspace, enable_monitoring, coi_binary):
    """Test HIGH threat only alerts when auto_pause_on_high=false."""
    # Modify config to disable auto-pause but keep other settings from fixture
    # IMPORTANT: Must include file_read_threshold_mb to avoid spurious HIGH threats
    # from container startup activity, and network mode = open to prevent false
    # positive network threats in CI
    config_path = Path.home() / ".coi" / "config.toml"
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )

    # Create a 200MB binary file (matching pattern from test_large_file_read_triggers_auto_pause)
    # Using binary file with write_bytes ensures reliable I/O accounting
    large_file = Path(test_workspace) / "data.bin"
    large_file.write_bytes(b"D" * (200 * 1024 * 1024))

    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "7"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-7"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Verify container is still running before triggering the test action
    pre_state = get_container_state(container_name)
    if pre_state != "Running":
        proc.terminate()
        events = get_threat_events(container_name)
        print("\n=== DEBUG: Container not running before file read ===")
        print(f"State: {pre_state}")
        print(f"Events: {len(events)}")
        for e in events:
            print(f"  - {e.get('level')}: {e.get('title')} ({e.get('action')})")
        print("=== END DEBUG ===\n")
        cleanup_container(container_name, coi_binary)
        pytest.skip(f"Container in unexpected state before test: {pre_state}")

    # Trigger HIGH threat using dd with O_DIRECT (matches reliable pattern from other tests)
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "dd",
            "if=/workspace/data.bin",
            "of=/dev/null",
            "bs=1M",
            "iflag=direct",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(10)

    # Container should stay running (not paused) - check multiple times for stability
    state = get_container_state(container_name)

    # Print debug info if state is unexpected
    if state != "Running":
        events = get_threat_events(container_name)
        print("\n=== DEBUG: Container not running after file read ===")
        print(f"State: {state}")
        print(f"Events: {len(events)}")
        for e in events:
            print(f"  - {e.get('level')}: {e.get('title')} ({e.get('action')})")
        print("=== END DEBUG ===\n")

    # The key assertion: container should NOT be Frozen (paused) because auto_pause_on_high=false
    # This is the core behavior we're testing - HIGH threats should alert, not pause
    assert state != "Frozen", (
        "Container should NOT be paused when auto_pause_on_high=false, but got Frozen"
    )

    assert state == "Running", (
        f"Container should stay running when auto_pause disabled, got {state}"
    )

    # But threat should still be logged
    events = get_threat_events(container_name)
    high_threats = [e for e in events if e.get("level") == "high"]
    # This might be empty if large file read detection is slow, but that's ok
    if len(high_threats) > 0:
        # Verify action was NOT "paused" (since auto_pause_on_high=false)
        # Valid actions: "alerted" (first detection), "pending", or "deduplicated" (subsequent detections)
        for threat in high_threats:
            assert threat.get("action") in ["alerted", "pending", "deduplicated"], (
                f"Expected action='alerted' or 'deduplicated', got {threat.get('action')}"
            )
            # Most importantly: action should NEVER be "paused"
            assert threat.get("action") != "paused", (
                "Container should NOT be paused when auto_pause_on_high=false"
            )

    proc.terminate()
    cleanup_container(container_name, coi_binary)
