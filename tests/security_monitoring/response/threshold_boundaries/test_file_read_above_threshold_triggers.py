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
def test_file_read_above_threshold_triggers(
    test_workspace, enable_monitoring_low_thresholds, coi_binary
):
    """Test that reading 250MB (above threshold) triggers HIGH threat.

    Uses 250MB to guarantee >50MB per poll interval at any realistic disk
    speed (30-200 MB/s).  Even in the worst case (200 MB/s, read completes
    in ~1.25s straddling one 1s poll boundary), each half is ~125MB which
    comfortably exceeds the 50MB threshold.
    """
    # Create 250MB file (well above threshold).
    large_file = Path(test_workspace) / "data250mb.bin"
    large_file.write_bytes(b"C" * (250 * 1024 * 1024))

    # Capture stderr for debugging
    stderr_file = Path("/tmp") / "coi-test-250mb-above-debug.log"
    stderr_fd = open(stderr_file, "w")  # noqa: SIM115

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "29",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=stderr_fd,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-29"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        stderr_fd.close()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # IMPORTANT: Wait for monitoring to establish stable baseline
    time.sleep(10)

    # Read the 250MB file with dd and direct I/O to bypass page cache.
    # Use Popen (non-blocking) because the monitoring daemon may freeze the
    # container mid-read, which would cause a blocking subprocess.run to
    # hang until timeout.
    dd_proc = subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "dd",
            "if=/workspace/data250mb.bin",
            "of=/dev/null",
            "bs=1M",
            "iflag=direct",  # Bypass cache to ensure actual I/O
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Poll for the container to be frozen.  The monitoring daemon (1s poll
    # interval) will detect the >50MB delta and freeze the container either
    # during or shortly after the dd read completes.
    paused = False
    for _ in range(30):
        time.sleep(1)
        state = get_container_state(container_name)
        if state == "Frozen":
            paused = True
            dd_proc.kill()
            break

    # Close stderr and print debug log BEFORE assertions
    proc.terminate()
    stderr_fd.close()

    print("\n=== Coi 250MB Above-Threshold Read Debug Log ===")
    if stderr_file.exists():
        print(stderr_file.read_text())
    print("=== End Debug Log ===\n")

    assert paused, "Container should be paused on 250MB read (above threshold)"

    # Verify HIGH threat logged
    events = get_threat_events(container_name)
    high_fs = [e for e in events if e.get("level") == "high" and e.get("category") == "filesystem"]
    assert len(high_fs) > 0, "250MB read should trigger HIGH filesystem threat"

    cleanup_container(container_name, coi_binary)
