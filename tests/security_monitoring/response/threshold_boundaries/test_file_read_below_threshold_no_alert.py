"""Test detector behavior at threshold boundaries."""

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


def test_file_read_below_threshold_no_alert(
    test_workspace, enable_monitoring_high_read_threshold, coi_binary
):
    """Test that a 100MB read (well below the 500MB threshold) doesn't trigger.

    Detection compares a per-interval delta of the container's *whole-tree*
    cgroup read counter against the threshold, so background container I/O
    (dockerd/containerd/journald/apt) in the same 1s poll interval is counted
    too. Against a 50MB threshold that background burst alone crossed the
    line and froze the container regardless of the test's own read size —
    shrinking the read 49→30→10MB never stabilized it (#738). This test now
    runs against a 500MB threshold (see the fixture), which no plausible 1s
    interval of background reads can fill, so a genuinely large 100MB read
    deterministically stays below it while still exercising the read path.
    Above-threshold detection is covered by the large-read tests.
    """
    # Create a 100MB file — a substantial read, still far below 500MB.
    large_file = Path(test_workspace) / "data100mb.bin"
    large_file.write_bytes(b"A" * (100 * 1024 * 1024))

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "27",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-27"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize (15s to ensure startup I/O settles)
    time.sleep(15)

    # Read the 100MB file
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "cat",
            "/workspace/data100mb.bin",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for potential detection
    time.sleep(10)

    # Container should still be running (below threshold)
    state = get_container_state(container_name)

    if state == "Unknown":
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
            proc.wait()
        cleanup_container(container_name, coi_binary)
        pytest.skip(
            f"Container {container_name} vanished during test (state=Unknown). "
            "This is a CI infrastructure issue, not a test failure."
        )

    assert state == "Running", (
        f"Container should stay running for 100MB read (below 500MB threshold), got {state}."
    )

    # No HIGH filesystem threats
    events = get_threat_events(container_name)
    high_fs = [e for e in events if e.get("level") == "high" and e.get("category") == "filesystem"]
    assert len(high_fs) == 0, "100MB read should not trigger HIGH threat (threshold is 500MB)"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
