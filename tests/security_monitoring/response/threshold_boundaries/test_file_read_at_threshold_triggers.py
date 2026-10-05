"""Test detector behavior at threshold boundaries."""

import os
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


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") == "true",
    reason="cgroup io.stat does not track bind-mount I/O on GitHub Actions runners; "
    "reads from /workspace are served from the host page cache and not attributed "
    "to the container's cgroup, so the monitoring daemon sees 0 bytes read.",
)
def test_file_read_at_threshold_triggers(
    test_workspace, enable_monitoring_low_thresholds, coi_binary
):
    """Test that reading above 50MB threshold triggers HIGH threat."""
    # Create 75MB file (above 50MB threshold).
    # Using 75MB instead of 55MB because at typical CI disk speeds (~60 MB/s),
    # smaller files can be read in ~1 second and straddle two monitoring poll
    # intervals, causing each per-poll delta to land below the 50MB threshold.
    # 75MB ensures the first monitoring poll captures ≥50MB delta regardless
    # of when the poll fires, while still being a "near threshold" test
    # (vs the 100MB "well above threshold" test).
    large_file = Path(test_workspace) / "data75mb.bin"
    large_file.write_bytes(b"B" * (75 * 1024 * 1024))

    # Capture stderr for debugging
    stderr_file = Path("/tmp") / "coi-test-75mb-debug.log"
    stderr_fd = open(stderr_file, "w")  # noqa: SIM115

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "28",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=stderr_fd,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-28"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        stderr_fd.close()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # IMPORTANT: Wait for monitoring to establish stable baseline
    # Container startup I/O can take 10-15 seconds to settle
    time.sleep(10)

    # Read the 75MB file using dd with direct I/O to bypass cache
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "dd",
            "if=/workspace/data75mb.bin",
            "of=/dev/null",
            "bs=1M",
            "iflag=direct",  # Bypass cache to ensure actual I/O
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for detection and pause with extended polling budget.
    # On slow CI runners, monitoring detection can take longer due to
    # disk I/O contention and polling interval alignment.
    time.sleep(10)

    paused = False
    for _ in range(30):
        time.sleep(1)
        state = get_container_state(container_name)
        if state == "Frozen":
            paused = True
            break

    # Close stderr and print debug log BEFORE assertions
    proc.terminate()
    stderr_fd.close()

    print("\n=== Coi 75MB Read Debug Log ===")
    if stderr_file.exists():
        print(stderr_file.read_text())
    print("=== End Debug Log ===\n")

    assert paused, "Container should be paused on 75MB read (above threshold)"

    # Verify HIGH threat logged
    events = get_threat_events(container_name)
    high_fs = [e for e in events if e.get("level") == "high" and e.get("category") == "filesystem"]
    assert len(high_fs) > 0, "75MB read should trigger HIGH filesystem threat"

    cleanup_container(container_name, coi_binary)
