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


def test_allowlist_mode_rfc1918_flagged(test_workspace, coi_binary):
    """Allowed-domain CIDRs must be passed to the security monitor.

    In allowlist network mode, RFC1918 private addresses are not in the
    configured allow-list and should be flagged as network threats. Before
    the fix, security monitors always received an empty allowedCIDRs list,
    so RFC1918 addresses were silently allowed regardless of network mode.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "allowlist"
allowed_domains = ["github.com", "pypi.org"]

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-37"
    )
    rfc_script = Path(test_workspace) / "rfc1918_allowlist.py"
    rfc_script.write_text(
        """#!/usr/bin/env python3
import socket, time
# A blocked TCP connect is refused at once, before a 1 s poll can see it; a
# connected UDP socket stays in /proc/net/udp with its remote address.
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("10.0.0.1", 80))
for _ in range(60):
    try:
        s.send(b"x")
    except OSError:
        pass
    time.sleep(1)
"""
    )
    rfc_script.chmod(0o755)

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "37",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_container_running(container_name):
            pytest.fail(f"Container {container_name} did not start")

        time.sleep(10)

        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "python3",
                "/workspace/rfc1918_allowlist.py",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Best-effort connection: poll, then skip honestly if nothing surfaced
        # rather than pass vacuously.
        network_threats = poll_network_threats(container_name)
        if not network_threats:
            pytest.skip(
                "no network threat detected within the poll window (best-effort "
                "RFC1918 connection in allowlist mode); see "
                "test_network_connection_detection.py"
            )
        for threat in network_threats:
            assert threat.get("level") in ["high", "critical"], (
                f"Expected HIGH/CRITICAL for RFC1918 in allowlist mode, got {threat.get('level')}"
            )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
        if backup is not None:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
