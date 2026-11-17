"""Allowlist mode + a LAN [[network.hosts]] entry: the monitor must not treat the
configured LAN service as a private-network threat (which auto-pauses the
container), while still seeing other threats on that same host."""

import time
from pathlib import Path

from support.helpers import fake_lan
from support.monitoring import (
    cleanup_container,
    get_container_state,
    get_threat_events,
    hold_connect,
    is_c2_port_threat,
    start_shell,
    wait_for_threats,
)

SLOT = 71


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
            holders.append(hold_connect(container_name, "redmine.lan", 443))
            time.sleep(15)
            assert get_container_state(container_name) == "Running", (
                "a connection to the configured LAN service must not pause the container; "
                f"threat events: {get_threat_events(container_name)}"
            )
            flagged = [
                e for e in get_threat_events(container_name) if redmine in e.get("description", "")
            ]
            assert not flagged, f"redmine.lan:443 must not be flagged, got: {flagged}"

            # Positive control on the SAME host: a known C2 port must still be
            # flagged, proving the monitor sees this traffic and that exempting the
            # host from the private-network check did not blind the other checks.
            holders.append(hold_connect(container_name, "redmine.lan", 4444))
            threats = wait_for_threats(container_name, is_c2_port_threat(redmine))
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
