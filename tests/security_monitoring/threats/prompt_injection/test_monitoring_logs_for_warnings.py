"""Test realistic prompt injection scenario - code inside container goes rogue."""

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


def test_monitoring_logs_for_warnings(test_workspace, enable_monitoring, coi_binary):
    """Verify monitoring logs contain WARNING messages, not just audit logs."""
    # Start shell - monitoring is enabled via enable_monitoring fixture config
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "5",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-5"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Inject env scanning process directly (simulates environment scanning - WARNING level)
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'env' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for detection
    time.sleep(5)

    # Container should still be running (WARNING doesn't kill)
    # Retry a few times to handle transient incus list hiccups
    state = "Unknown"
    for _ in range(10):
        state = get_container_state(container_name)
        if state == "Running":
            break
        time.sleep(1)
    assert state == "Running", f"Container should stay running on WARNING, got {state}"

    # Verify WARNING in audit log
    events = get_threat_events(container_name)
    warnings = [e for e in events if e.get("level") == "warning"]
    assert len(warnings) > 0, "Expected WARNING event in audit log"

    # Check that audit log has proper structure
    for warning in warnings:
        assert "timestamp" in warning, "Audit event missing timestamp"
        assert "description" in warning, "Audit event missing description"
        assert "level" in warning, "Audit event missing level"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
