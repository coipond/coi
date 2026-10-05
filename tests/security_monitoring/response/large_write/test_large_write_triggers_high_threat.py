"""Test large write detection for data exfiltration prevention."""

import os
import subprocess
import time

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
    "writes to /workspace go through the host page cache and are not attributed "
    "to the container's cgroup, so the monitoring daemon sees 0 bytes written.",
)
def test_large_write_triggers_high_threat(
    test_workspace, enable_monitoring_low_thresholds, coi_binary
):
    """Test that large writes (potential data exfiltration) trigger HIGH threat."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "42",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-42"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize (15s to ensure startup I/O settles)
    time.sleep(15)

    # Write a large file (200MB) - potential data exfiltration
    # Use bs=50M count=4 so writes clearly exceed the 50MB threshold
    # in a single poll interval. Avoid oflag=direct as it can fail
    # silently in some container configurations.
    # Note: The dd command may timeout or be interrupted if monitoring pauses/kills container
    try:
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "dd",
                "if=/dev/zero",
                "of=/workspace/exfiltration_test.bin",
                "bs=50M",
                "count=4",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass  # Expected if monitoring pauses/stops the container

    # Give dd a moment to start writing before polling
    time.sleep(2)

    # Poll for HIGH threat event or Frozen state instead of blind sleep
    write_threat_found = False
    for _ in range(30):
        time.sleep(1)
        events = get_threat_events(container_name)
        write_threats = [
            e
            for e in events
            if e.get("level") == "high"
            and e.get("category") == "filesystem"
            and "write" in e.get("title", "").lower()
        ]
        if len(write_threats) > 0:
            write_threat_found = True
            break
        # Container may be paused/frozen on HIGH threat
        state = get_container_state(container_name)
        if state == "Frozen":
            # Give one more second for audit log flush
            time.sleep(1)
            events = get_threat_events(container_name)
            write_threats = [
                e
                for e in events
                if e.get("level") == "high"
                and e.get("category") == "filesystem"
                and "write" in e.get("title", "").lower()
            ]
            if len(write_threats) > 0:
                write_threat_found = True
            break

    proc.terminate()

    if not write_threat_found:
        events = get_threat_events(container_name)
        print("\n=== Large Write Test Debug ===")
        print(f"Container state: {get_container_state(container_name)}")
        print(f"Total events: {len(events)}")
        for event in events:
            print(
                f"- level={event.get('level')}, category={event.get('category')}, "
                f"title={event.get('title')}"
            )
        print("=== End Debug ===\n")

    assert write_threat_found, (
        f"Expected HIGH threat for 200MB write, got {len(write_threats)} write threats. "
        "Large writes should be detected as potential data exfiltration."
    )

    cleanup_container(container_name, coi_binary)
