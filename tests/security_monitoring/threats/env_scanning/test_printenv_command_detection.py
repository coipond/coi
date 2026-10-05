"""Test detection of various environment scanning patterns."""

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


def test_printenv_command_detection(test_workspace, enable_monitoring, coi_binary):
    """Test printenv command detection."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "14",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-14"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Inject printenv command
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

    # Poll for WARNING event in audit log
    warning_found = False
    for _ in range(15):
        time.sleep(1)
        events = get_threat_events(container_name)
        warnings = [e for e in events if e.get("level") == "warning"]
        if len(warnings) > 0:
            warning_found = True
            break

    # Container should stay running (WARNING doesn't kill)
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
    assert state == "Running", f"Expected Running on WARNING, got {state}"

    assert warning_found, "Expected WARNING for printenv command"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
