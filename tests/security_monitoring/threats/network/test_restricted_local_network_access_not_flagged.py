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

from support.helpers import fake_lan
from support.monitoring import (
    assert_established,
    get_container_state,
    get_threat_events,
    hold_connect,
    is_c2_port_threat,
    is_metadata_threat,
    monitored_shell,
    wait_for_threats,
)

SLOT = 74


CONFIG = """
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


def test_restricted_local_network_access_not_flagged(test_workspace, coi_binary):
    with (
        fake_lan("192.168.206", hosts=(20,), ports=(443, 4444)) as (lan_host,),
        monitored_shell(test_workspace, coi_binary, SLOT, CONFIG) as (container_name, holders),
    ):
        holders.append(hold_connect(container_name, lan_host, 443))
        assert_established(container_name, holders[-1], lan_host, 443)
        time.sleep(15)
        assert get_container_state(container_name) == "Running", (
            "LAN traffic under allow_local_network_access must not pause the container; "
            f"threat events: {get_threat_events(container_name)}"
        )
        flagged = [
            e
            for e in get_threat_events(container_name)
            if f"{lan_host}:443" in e.get("description", "")
        ]
        assert not flagged, f"{lan_host}:443 must not be flagged, got: {flagged}"

        # Positive controls (CRITICAL, alert only here).
        holders.append(hold_connect(container_name, lan_host, 4444))
        holders.append(hold_connect(container_name, "169.254.169.254", 80, proto="udp"))
        assert wait_for_threats(container_name, is_c2_port_threat(lan_host)), (
            f"port 4444 on the LAN host must still be flagged; "
            f"threat events: {get_threat_events(container_name)}"
        )
        assert wait_for_threats(container_name, is_metadata_threat), (
            f"169.254.169.254 must still be flagged; "
            f"threat events: {get_threat_events(container_name)}"
        )
