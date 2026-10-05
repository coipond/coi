"""Test threat detection for different attack types."""

import subprocess
import time

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
)


def test_env_scanning_detection(test_workspace, enable_monitoring, coi_binary):
    """Test environment scanning detection (WARNING level)."""
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", test_workspace, "--slot", "2", "--debug"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-2"

    # Wait for container to be running
    container_ready = False
    for _ in range(30):
        state = get_container_state(container_name)
        if state == "Running":
            container_ready = True
            break
        time.sleep(1)

    if not container_ready:
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Inject env scanning command
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

    # Poll for WARNING event in audit log
    warning_found = False
    for _ in range(15):
        time.sleep(1)
        events = get_threat_events(container_name)
        warnings = [e for e in events if e.get("level") == "warning"]
        if len(warnings) > 0:
            warning_found = True
            break

    # Container should still be running (WARNING doesn't kill)
    state = get_container_state(container_name)
    assert state == "Running", f"Expected Running on WARNING, got {state}"

    if not warning_found:
        events = get_threat_events(container_name)
        print("\n=== DEBUG: env scanning test - no warning found ===")
        print(f"Container state: {state}")
        print(f"Total threat events: {len(events)}")
        for event in events:
            print(
                f"  - level={event.get('level')}, category={event.get('category')}, "
                f"desc={event.get('description', 'N/A')[:80]}"
            )
        print("=== END DEBUG ===\n")

    assert warning_found, "Expected WARNING event for env scanning"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
