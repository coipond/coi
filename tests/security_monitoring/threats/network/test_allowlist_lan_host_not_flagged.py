"""Allowlist mode + a LAN [[network.hosts]] entry: the monitor must not treat the
configured LAN service as a private-network threat (which auto-pauses the
container), while still seeing other threats on that same host."""

import subprocess
import time
from pathlib import Path

from support.helpers import fake_lan
from support.monitoring import (
    cleanup_container,
    get_container_state,
    get_threat_events,
    start_shell,
)

SLOT = 71


def _hold_connection(container_name, host, port, seconds=60):
    """Keep one ESTABLISHED TCP connection open from inside the container, so the
    monitor (which samples the container's socket table) is sure to see it."""
    return subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "python3",
            "-c",
            "import socket, time; "
            f"s = socket.create_connection(({host!r}, {port}), timeout=5); "
            f"time.sleep({seconds})",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _threats_about(container_name, ip):
    return [e for e in get_threat_events(container_name) if ip in e.get("description", "")]


def test_allowlist_lan_host_not_flagged(test_workspace, coi_binary):
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    with fake_lan("192.168.204", hosts=(20,), ports=(443, 4444)) as (redmine,):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            f"""
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1/32"]

[[network.hosts]]
ip = "{redmine}"
hostnames = ["redmine.lan"]
ports = [443, 4444]

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
        )
        container_name, proc = start_shell(test_workspace, coi_binary, SLOT)
        holders = []
        try:
            # The configured service: held open across many poll cycles, it must
            # raise nothing, and the container must keep running (not be paused).
            holders.append(_hold_connection(container_name, "redmine.lan", 443))
            time.sleep(15)
            assert get_container_state(container_name) == "Running", (
                "a connection to the configured LAN service must not pause the container"
            )
            flagged = _threats_about(container_name, redmine)
            assert not flagged, f"redmine.lan:443 must not be flagged, got: {flagged}"

            # Positive control on the SAME host: a known C2 port must still be
            # flagged, proving the monitor sees this traffic and that exempting the
            # host from the private-network check did not blind the other checks.
            holders.append(_hold_connection(container_name, "redmine.lan", 4444))
            threats = []
            deadline = time.monotonic() + 45
            while not threats and time.monotonic() < deadline:
                threats = _threats_about(container_name, f"{redmine}:4444")
                time.sleep(2)
            assert threats, "a C2-port connection to the LAN host must still be flagged"
            assert all("RFC1918" not in t.get("description", "") for t in threats), (
                f"the LAN host must not be reported as an RFC1918 threat: {threats}"
            )
        finally:
            for h in holders:
                h.terminate()
            proc.terminate()
            cleanup_container(container_name, coi_binary)
            if backup is not None:
                config_path.write_text(backup)
            elif config_path.exists():
                config_path.unlink()
