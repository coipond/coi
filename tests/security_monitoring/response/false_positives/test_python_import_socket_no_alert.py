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


def test_python_import_socket_no_alert(test_workspace, enable_monitoring, coi_binary):
    """Test that importing socket without using it doesn't trigger."""
    # Create a script that imports socket but doesn't use it maliciously
    benign_script = Path(test_workspace) / "benign.py"
    benign_script.write_text(
        """#!/usr/bin/env python3
import socket
import time

# Just print something benign
print("Hello world")
time.sleep(2)
"""
    )
    benign_script.chmod(0o755)

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "25",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-25"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Run the benign script
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "python3",
            "/workspace/benign.py",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(5)

    # Container should still be running
    state = get_container_state(container_name)
    assert state == "Running", "Benign python script should not trigger alerts"

    # No CRITICAL reverse shell alerts
    events = get_threat_events(container_name)
    critical = [e for e in events if e.get("level") == "critical"]

    # Reverse shell detection requires network activity, not just socket import
    reverse_shells = [e for e in critical if "reverse shell" in e.get("title", "").lower()]
    assert len(reverse_shells) == 0, "Importing socket without network activity should not trigger"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
