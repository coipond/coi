"""Test detection of various reverse shell patterns."""

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


def test_python_reverse_shell_detection(test_workspace, enable_monitoring, coi_binary):
    """Test Python reverse shell pattern detection."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "10",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-10"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Inject Python reverse shell pattern
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'python -c socket.socket' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for detection and kill
    time.sleep(5)

    killed = False
    for _ in range(15):
        time.sleep(1)
        state = get_container_state(container_name)
        if container_absent(container_name):
            killed = True
            break

    assert killed, (
        f"Container should be killed (stopped AND deleted) on Python reverse shell detection (final observed state: {state!r})"
    )

    # Verify threat logged
    events = get_threat_events(container_name)
    critical = [e for e in events if e.get("level") == "critical"]
    assert len(critical) > 0, "Expected CRITICAL threat for Python reverse shell"

    # Verify pattern mentioned in threat
    threats_text = " ".join([e.get("description", "") for e in critical])
    assert "python" in threats_text.lower(), "Expected 'python' in threat description"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
