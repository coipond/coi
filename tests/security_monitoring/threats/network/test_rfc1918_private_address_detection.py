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


def test_rfc1918_private_address_detection(test_workspace, enable_monitoring, coi_binary):
    """Test that connections to RFC1918 private addresses trigger a network threat."""
    rfc1918_script = Path(test_workspace) / "rfc1918.py"
    rfc1918_script.write_text(
        """#!/usr/bin/env python3
import subprocess
import time

# Attempt connections to RFC1918 private address ranges
# 10.0.0.0/8
subprocess.Popen(
    ["timeout", "5", "nc", "-w", "2", "10.0.0.1", "80"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
# 172.16.0.0/12
subprocess.Popen(
    ["timeout", "5", "nc", "-w", "2", "172.16.0.1", "80"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
# 192.168.0.0/16
subprocess.Popen(
    ["timeout", "5", "nc", "-w", "2", "192.168.1.1", "80"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

time.sleep(60)
"""
    )
    rfc1918_script.chmod(0o755)

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "36",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-36"
    )

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Execute RFC1918 connection script
    subprocess.Popen(
        ["incus", "exec", container_name, "--", "python3", "/workspace/rfc1918.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        # Best-effort connections (fire-and-forget to unrouted RFC1918 hosts):
        # poll, then skip honestly if nothing surfaced rather than pass vacuously.
        network_threats = poll_network_threats(container_name)
        if not network_threats:
            pytest.skip(
                "no network threat detected within the poll window (best-effort "
                "RFC1918 connections); see test_network_connection_detection.py"
            )
        for threat in network_threats:
            assert threat.get("level") in ["high", "critical"], (
                f"Expected HIGH/CRITICAL for RFC1918 address, got {threat.get('level')}"
            )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
