"""Test for coi shell - restricted mode with allow_local_network_access = true
and the nft monitor on: LAN traffic the firewall accepts must not pause the
container.

Tests that:
- an ESTABLISHED connection to a LAN host raises no private-network threat and
  the container keeps running, with auto-pause on;
- beside it, port 4444 on the same LAN host and 169.254.169.254 are still
  flagged. Every RFC1918 host is permitted here, so there is no unpermitted
  LAN host control."""

import time
from pathlib import Path

from support.helpers import fake_lan
from support.monitoring import (
    cleanup_container,
    get_container_state,
    get_threat_events,
    hold_connect,
    is_metadata_threat,
    start_shell,
    wait_for_threats,
)

SLOT = 74


def test_restricted_local_network_access_not_flagged(test_workspace, coi_binary):
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    with fake_lan("192.168.206", hosts=(20,), ports=(443, 4444)) as (lan_host,):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            """
[network]
mode = "restricted"
allow_local_network_access = true

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = false

[monitoring.nft]
enabled = true
"""
        )
        container_name, proc = start_shell(test_workspace, coi_binary, SLOT)
        holders = []
        try:
            holders.append(hold_connect(container_name, lan_host, 443))
            time.sleep(15)
            assert get_container_state(container_name) == "Running", (
                "LAN traffic under allow_local_network_access must not pause the container; "
                f"threat events: {get_threat_events(container_name)}"
            )
            flagged = [e for e in get_threat_events(container_name) if f"{lan_host}:443" in str(e)]
            assert not flagged, f"{lan_host}:443 must not be flagged, got: {flagged}"

            # Positive controls (CRITICAL, alert only here).
            holders.append(hold_connect(container_name, lan_host, 4444))
            holders.append(hold_connect(container_name, "169.254.169.254", 80))
            assert wait_for_threats(
                container_name, lambda e: lan_host in str(e) and "4444" in str(e)
            ), (
                f"port 4444 on the LAN host must still be flagged; "
                f"threat events: {get_threat_events(container_name)}"
            )
            assert wait_for_threats(container_name, is_metadata_threat), (
                f"169.254.169.254 must still be flagged; "
                f"threat events: {get_threat_events(container_name)}"
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
