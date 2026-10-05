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


def test_suspicious_port_high_threat(test_workspace, enable_monitoring, coi_binary):
    """Test connection to suspicious ports (1234, 31337) triggers HIGH/CRITICAL threat."""
    port_script = Path(test_workspace) / "suspicious_port.py"
    port_script.write_text(
        """#!/usr/bin/env python3
import subprocess
import time

# Connect to port 1234 (common reverse shell port, HIGH threat)
subprocess.Popen(
    ["timeout", "30", "nc", "-w", "2", "8.8.8.8", "1234"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

# Connect to port 31337 (elite/leet port, HIGH threat)
subprocess.Popen(
    ["timeout", "30", "nc", "-w", "2", "8.8.8.8", "31337"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

time.sleep(60)
"""
    )
    port_script.chmod(0o755)

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "35",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-35"
    )

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Execute suspicious port connection script
    subprocess.Popen(
        ["incus", "exec", container_name, "--", "python3", "/workspace/suspicious_port.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        # Best-effort connection (fire-and-forget to an external host): poll,
        # then skip honestly if nothing surfaced rather than pass vacuously.
        network_threats = poll_network_threats(container_name)
        if not network_threats:
            pytest.skip(
                "no network threat detected within the poll window (best-effort "
                "suspicious-port connection); see test_network_connection_detection.py"
            )
        for threat in network_threats:
            assert threat.get("level") in ["high", "critical"], (
                f"Expected HIGH/CRITICAL for suspicious port, got {threat.get('level')}"
            )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
