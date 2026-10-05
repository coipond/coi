"""Test that legitimate commands don't trigger false alerts."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_normal_build_operations_no_alert(test_workspace, enable_monitoring, coi_binary):
    """Test that normal development operations don't trigger alerts."""
    # Create a simple build script
    build_script = Path(test_workspace) / "build.sh"
    build_script.write_text(
        """#!/bin/bash
# Normal build operations
echo "Building..."
ls -la
cat package.json 2>/dev/null || echo "No package.json"
echo "Build complete"
"""
    )
    build_script.chmod(0o755)

    # Create a small package.json
    package_json = Path(test_workspace) / "package.json"
    package_json.write_text('{"name": "test", "version": "1.0.0"}')

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "26",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-26"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Run build script
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "/workspace/build.sh",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(5)

    # Container should still be running
    state = get_container_state(container_name)

    # DEBUG: Print all threats if container was killed
    if state != "Running":
        events = get_threat_events(container_name)
        print(f"\n=== DEBUG: Container killed unexpectedly (state={state}) ===")
        print(f"Total threat events: {len(events)}")
        for i, event in enumerate(events):
            print(
                f"Threat {i + 1}: level={event.get('level')}, "
                f"category={event.get('category')}, "
                f"title={event.get('title')}, "
                f"description={event.get('description')}"
            )
        print("=== END DEBUG ===\n")

    assert state == "Running", f"Normal build operations should not trigger alerts (state={state})"

    # No high-level threats from normal operations
    events = get_threat_events(container_name)
    high_or_critical = [e for e in events if e.get("level") in ["high", "critical"]]

    # Normal ls, cat, echo shouldn't trigger high/critical
    if len(high_or_critical) > 0:
        print("\n=== DEBUG: Unexpected high/critical threats ===")
        for event in high_or_critical:
            print(f"- {event}")
        print("=== END DEBUG ===\n")

    assert len(high_or_critical) == 0, (
        f"Normal build operations should not trigger high/critical alerts. "
        f"Found {len(high_or_critical)} threats: {[e.get('title') for e in high_or_critical]}"
    )

    proc.terminate()
    cleanup_container(container_name, coi_binary)
