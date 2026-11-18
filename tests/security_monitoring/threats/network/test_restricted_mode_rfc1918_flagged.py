"""Test for coi shell - restricted mode with the nft monitor off: the process
monitor flags a LAN host the firewall blocks.

Tests that:
- a connected UDP socket to a LAN host that is not permitted raises a HIGH
  RFC1918 threat from the process monitor;
- beside it, an ESTABLISHED connection to a [[network.hosts]] service on the
  same LAN raises none, so the firewall permits still reach the process
  monitor without the nft monitor."""

import time

from support.helpers import fake_lan
from support.monitoring import (
    assert_established,
    get_threat_events,
    hold_connect,
    monitored_shell,
    wait_for_threats,
)

SLOT = 76


def _config(lan_host):
    return f"""
[network]
mode = "restricted"

[[network.hosts]]
ip = "{lan_host}"
hostnames = ["service.lan"]
ports = [443]

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false

[monitoring.nft]
enabled = false
"""


def test_restricted_mode_rfc1918_flagged(test_workspace, coi_binary):
    with (
        fake_lan("192.168.207", hosts=(20, 21), ports=(443,)) as (service, blocked),
        monitored_shell(test_workspace, coi_binary, SLOT, _config(service)) as (
            container_name,
            holders,
        ),
    ):
        holders.append(hold_connect(container_name, service, 443))
        assert_established(container_name, holders[-1], service, 443)

        holders.append(hold_connect(container_name, blocked, 443, proto="udp"))
        threats = wait_for_threats(
            container_name,
            lambda e: (
                f"{blocked}:443" in e.get("description", "")
                and "RFC1918" in e.get("description", "")
            ),
        )
        assert threats, (
            f"{blocked}:443 must be flagged as RFC1918 in restricted mode; "
            f"threat events: {get_threat_events(container_name)}"
        )
        assert all(t.get("level") == "high" for t in threats), threats

        time.sleep(5)
        flagged = [
            e
            for e in get_threat_events(container_name)
            if f"{service}:443" in e.get("description", "")
        ]
        assert not flagged, f"the permitted {service}:443 must not be flagged, got: {flagged}"
