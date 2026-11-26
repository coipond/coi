"""Test for coi shell - connection attempts the firewall rejects.

Tests that:
- attempts to rejected_burst_destinations distinct destinations the firewall
  rejects raise a HIGH threat from the process monitor, while each attempt
  before them is a WARNING."""

from support.monitoring import (
    get_threat_events,
    hold_connect,
    monitored_shell,
    wait_for_threats,
)

SLOT = 83
DESTINATIONS = ("10.0.0.1", "10.0.0.2", "10.0.0.3")

_CONFIG = f"""
[network]
mode = "allowlist"
allowed_domains = ["github.com"]

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
rejected_burst_destinations = {len(DESTINATIONS)}

[monitoring.nft]
enabled = false
"""


def test_rejected_burst_high(test_workspace, coi_binary):
    with monitored_shell(test_workspace, coi_binary, SLOT, _CONFIG) as (container_name, holders):
        # Connected UDP sockets stay in /proc/net/udp; a rejected TCP connect
        # is gone before a poll sees it.
        for ip in DESTINATIONS:
            holders.append(hold_connect(container_name, ip, 80, proto="udp"))
        threats = wait_for_threats(
            container_name,
            lambda e: (
                e.get("level") == "high"
                and "distinct rejected destinations" in e.get("description", "")
            ),
        )
        assert threats, (
            f"no HIGH burst threat for {DESTINATIONS}; "
            f"threat events: {get_threat_events(container_name)}"
        )
        rejected = [
            e
            for e in get_threat_events(container_name)
            if "rejected by the firewall" in e.get("description", "")
        ]
        # The first attempt counted is always below the threshold.
        assert "warning" in {e.get("level") for e in rejected}, rejected
