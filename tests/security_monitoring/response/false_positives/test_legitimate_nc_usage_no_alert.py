"""Test that legitimate commands don't trigger false alerts."""

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


def test_legitimate_nc_usage_no_alert(test_workspace, enable_monitoring, coi_binary):
    """Test that nc without -e flag doesn't trigger false alert."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "24",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-24"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Use nc for legitimate port listening (no -e, no network connection)
    # Just check if nc exists, don't actually listen
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "which nc || echo 'nc not found'",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(5)

    # Container should still be running
    state = get_container_state(container_name)
    assert state == "Running", f"Container should stay running on legitimate nc check, got {state}"

    # No CRITICAL threats should be logged for simple nc check
    events = get_threat_events(container_name)
    critical = [e for e in events if e.get("level") == "critical"]

    # If any critical events, they shouldn't be about nc without -e
    for event in critical:
        desc = event.get("description", "").lower()
        # Should not flag nc without suspicious patterns
        assert "nc" not in desc or "-e" in desc or "tcp" in desc, (
            f"nc without -e or network shouldn't trigger: {desc}"
        )

    proc.terminate()
    cleanup_container(container_name, coi_binary)
