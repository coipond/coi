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


def test_proc_environ_access_detection(test_workspace, enable_monitoring, coi_binary):
    """Test /proc/*/environ access detection."""
    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-18"
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "18",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_container_running(container_name, timeout=30):
            pytest.skip(f"Container {container_name} not found or not running")

        # Wait for monitoring baseline to stabilize
        time.sleep(10)

        # Inject command accessing /proc/*/environ
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'cat /proc/1/environ' sleep 30",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(5)

        # Container should stay running (WARNING level, not CRITICAL)
        state = get_container_state(container_name)
        assert state == "Running", f"Expected Running on WARNING, got {state}"

        # Verify WARNING for /proc/environ access
        events = get_threat_events(container_name)
        warnings = [e for e in events if e.get("level") == "warning"]
        assert len(warnings) > 0, "Expected WARNING for /proc/environ access"
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
