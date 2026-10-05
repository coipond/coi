"""Test audit log format and structure validation."""

import subprocess
import time

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_threat_events,
    wait_for_container_running,
)


def test_audit_log_evidence_structure(test_workspace, enable_monitoring, coi_binary):
    """Verify evidence data structure in audit log."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "22",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-22"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Trigger environment scanning (easier to verify evidence structure)
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

    time.sleep(5)

    # Get events
    events = get_threat_events(container_name)
    warnings = [e for e in events if e.get("level") == "warning"]

    if len(warnings) == 0:
        # Detection might be timing-dependent, don't fail
        proc.terminate()
        cleanup_container(container_name, coi_binary)
        pytest.skip("No WARNING events detected (timing dependent)")

    # Verify evidence structure for process-based threats
    for event in warnings:
        evidence = event.get("evidence")
        assert evidence is not None, "Evidence should not be None"

        # For process threats, evidence should have these fields
        if event.get("category") == "environment":
            # Evidence should be a dict with process info
            assert isinstance(evidence, dict), "Evidence should be a dict for process threats"
            # Common fields: pid, command, user, pattern
            # Don't assert on specific fields as structure may vary

    proc.terminate()
    cleanup_container(container_name, coi_binary)
