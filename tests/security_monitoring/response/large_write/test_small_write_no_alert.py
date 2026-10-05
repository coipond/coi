"""Test large write detection for data exfiltration prevention."""

import subprocess
import time

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_threat_events,
    wait_for_container_running,
)


def test_small_write_no_alert(test_workspace, enable_monitoring, coi_binary):
    """Test that small writes do NOT trigger alerts."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "43",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-43"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline
    time.sleep(10)

    # Write a small file (1MB) - normal operation
    subprocess.run(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "dd",
            "if=/dev/zero",
            "of=/workspace/small_file.bin",
            "bs=1M",
            "count=1",
        ],
        capture_output=True,
        timeout=30,
    )

    # Wait for monitoring cycles
    time.sleep(10)

    # Check that NO write threats were generated
    events = get_threat_events(container_name)
    write_threats = [
        e
        for e in events
        if e.get("category") == "filesystem" and "write" in e.get("title", "").lower()
    ]

    proc.terminate()

    assert len(write_threats) == 0, (
        f"Expected NO write threats for 1MB write, got {len(write_threats)}"
    )

    cleanup_container(container_name, coi_binary)
