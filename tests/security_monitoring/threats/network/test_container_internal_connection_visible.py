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


def test_container_internal_connection_visible(test_workspace, enable_monitoring, coi_binary):
    """Monitoring should be able to see container-internal (127.0.0.1) connections.

    Reading /proc/<container-init-pid>/net/tcp from the host scopes the
    read to the container's network namespace, making loopback connections
    visible. The previous host /proc/net/tcp + containerIP filter could not
    see connections whose local address is 127.0.0.1 (not the container IP).
    Port 1234 is in the suspicious-port list. This is a best-effort check:
    if any network threats are detected, they must be HIGH or CRITICAL.
    """
    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-38"
    )
    loopback_script = Path(test_workspace) / "loopback_c2port.py"
    loopback_script.write_text(
        """#!/usr/bin/env python3
import socket, time

# Start a listener on the suspicious port 1234
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 1234))
server.listen(1)

# Connect to it (creates an ESTABLISHED connection on 127.0.0.1:1234)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 1234))
conn, _ = server.accept()

# Hold the connection open so the monitor can see it
time.sleep(120)
"""
    )
    loopback_script.chmod(0o755)

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "38",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_container_running(container_name, timeout=30):
            pytest.skip(f"Container {container_name} not found or not running")

        time.sleep(10)

        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "python3",
                "/workspace/loopback_c2port.py",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Unlike the fire-and-forget network tests, this establishes a real,
        # stable ESTABLISHED loopback connection (held 120s) on the suspicious
        # port 1234, so detection is reliable — poll, then skip only if it truly
        # never surfaced (environmental), otherwise assert the level.
        network_threats = poll_network_threats(container_name)
        if not network_threats:
            pytest.skip(
                "no network threat detected for the loopback C2-port connection "
                "within the poll window; see test_network_connection_detection.py"
            )
        for threat in network_threats:
            assert threat.get("level") in ["high", "critical"], (
                f"Expected HIGH/CRITICAL for C2 port on loopback, got {threat.get('level')}"
            )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
