"""Test network-based threat detection."""

from support.monitoring import (
    get_container_state,
    get_threat_events,
    hold_connect,
    monitored_shell,
    wait_for_threats,
)

_CONFIG = """
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


def test_allowlist_mode_rfc1918_flagged(test_workspace, coi_binary):
    """Allowed-domain CIDRs must be passed to the security monitor.

    In allowlist network mode, RFC1918 private addresses are not in the
    configured allow-list and should be flagged as network threats. Before
    the fix, security monitors always received an empty allowedCIDRs list,
    so RFC1918 addresses were silently allowed regardless of network mode.
    The firewall rejects the attempt, so it is a WARNING and does not pause.
    """
    with monitored_shell(test_workspace, coi_binary, 37, _CONFIG) as (container_name, holders):
        # A blocked TCP connect is refused at once, before a 1 s poll can see
        # it; a connected UDP socket stays in /proc/net/udp.
        holders.append(hold_connect(container_name, "10.0.0.1", 80, proto="udp"))
        threats = wait_for_threats(
            container_name, lambda e: "10.0.0.1:80" in e.get("description", "")
        )
        assert threats, (
            "no threat for a connection to 10.0.0.1:80 in allowlist mode; "
            f"threat events: {get_threat_events(container_name)}"
        )
        for threat in threats:
            assert threat.get("level") == "warning", (
                f"Expected WARNING for a rejected RFC1918 attempt, got {threat.get('level')}"
            )
            assert "rejected by the firewall" in threat.get("description", ""), threat
        state = get_container_state(container_name)
        assert state == "Running", f"a WARNING must not pause the container, state is {state}"
