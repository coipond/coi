"""A connection from a nested network namespace is flagged like one from the
container's own namespace.

The holders run a UDP socket to a common C2 port (1234, HIGH): one from a
process that moved into a new network namespace (as `unshare -n` or a Docker
container does), one from the container's own namespace as a control. Both
must be flagged within the poll window.

The nested namespace gets the target address on its loopback device, so the
socket connects without a veth; connected UDP sends nothing."""

from pathlib import Path

from support.monitoring import (
    cleanup_container,
    get_threat_events,
    hold_script,
    poll_network_threats,
    start_shell,
)

SLOT = 77

HOLD = """
import os
import subprocess
import time
from socket import AF_INET, SOCK_DGRAM, socket

if {nested}:
    os.unshare(os.CLONE_NEWNET)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", "{host}/32", "dev", "lo"], check=True)
s = socket(AF_INET, SOCK_DGRAM)
s.connect(("{host}", 1234))
time.sleep(90)
"""

NESTED_HOST = "203.0.113.7"
MAIN_HOST = "203.0.113.8"


def test_nested_netns_connection_flagged(test_workspace, coi_binary):
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )
    container_name, proc = start_shell(test_workspace, coi_binary, SLOT)
    holders = []
    try:
        holders.append(hold_script(container_name, HOLD.format(nested=False, host=MAIN_HOST)))
        holders.append(hold_script(container_name, HOLD.format(nested=True, host=NESTED_HOST)))

        control = poll_network_threats(container_name, match=f"{MAIN_HOST}:1234")
        assert control, (
            "a C2-port socket in the container's own namespace must be flagged; "
            f"threat events: {get_threat_events(container_name)}"
        )
        nested = poll_network_threats(container_name, match=f"{NESTED_HOST}:1234")
        assert holders[1].poll() is None, "the nested-namespace socket must hold"
        assert nested, (
            "a C2-port socket in a nested network namespace must be flagged; "
            f"threat events: {get_threat_events(container_name)}"
        )
        assert all(t.get("level") == "high" for t in nested), nested
    finally:
        for h in holders:
            h.terminate()
        proc.terminate()
        cleanup_container(container_name, coi_binary)
        if backup is not None:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
