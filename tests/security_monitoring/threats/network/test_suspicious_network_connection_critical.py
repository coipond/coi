"""Test network-based threat detection."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    poll_network_threats,
    wait_for_container_running,
)


def test_suspicious_network_connection_critical(test_workspace, enable_monitoring, coi_binary):
    """Test connection to known C2 port triggers CRITICAL threat."""
    # Create script that connects to suspicious port
    network_script = Path(test_workspace) / "connect.py"
    network_script.write_text(
        """#!/usr/bin/env python3
import subprocess
import time

# Try to connect to known C2 port (4444)
# Use timeout to prevent hanging
subprocess.Popen(
    ["timeout", "30", "nc", "-w", "2", "8.8.8.8", "4444"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

time.sleep(60)
"""
    )
    network_script.chmod(0o755)

    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "8"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-8"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Execute connection script
    subprocess.Popen(
        ["incus", "exec", container_name, "--", "python3", "/workspace/connect.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        # Poll for a network-category threat instead of a single fixed sleep.
        # This is a best-effort connection (fire-and-forget to an external host
        # that need not accept it), so if nothing is detected we skip honestly
        # rather than pass vacuously. Reliable *unconditional* detection coverage
        # lives in test_network_connection_detection.py (which establishes a
        # stable ESTABLISHED connection); here we only validate the level when a
        # threat does surface.
        network_threats = poll_network_threats(container_name)
        if not network_threats:
            pytest.skip(
                "no network threat detected within the poll window (best-effort "
                "connection); see test_network_connection_detection.py for the "
                "reliable unconditional coverage"
            )
        for threat in network_threats:
            assert threat.get("level") in ["critical", "high"], (
                f"Expected CRITICAL/HIGH network threat, got {threat.get('level')}"
            )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
