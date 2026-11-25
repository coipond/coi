"""Allowlist mode + a LAN [[network.hosts]] entry with ports: neither monitor
treats the configured LAN service as a private-network threat, nor a permitted
port on it as a C2 port, while traffic outside the permit is still flagged.

Tests that:
- redmine.lan:443 and redmine.lan:8080 (8080 is a suspicious port, permitted
  explicitly by the entry's ports) raise no threat in either monitor;
- the same host on a suspicious port it has no permit for (4444) is flagged;
- a LAN host without an entry is flagged on 8080;
- a LAN host the firewall reaches on 8080 only through allowed_ports (an entry
  without ports) gets a C2-port alert: a firewall permit is not an explicit
  port permit."""

from support.helpers import fake_lan
from support.monitoring import (
    assert_established,
    get_threat_events,
    hold_connect,
    monitored_shell,
    wait_for_threats,
)

SLOT = 71


def _proc_threat(ip, port):
    """A process monitor threat about ip:port."""
    return lambda e: e.get("description", "").startswith(f"Connection to {ip}:{port}:")


def _proc_c2(ip, port):
    """A process monitor C2-port threat about ip:port."""
    return lambda e: e.get("description", "").startswith(
        f"Connection to {ip}:{port}: Suspicious port: {port} "
    )


def _nft_c2(ip, port):
    """An nft monitor C2-port threat about ip:port."""
    return lambda e: e.get("description", "") == f"C2/backdoor port {port} to {ip}"


def _nft_threat(ip, port):
    """An nft monitor threat about ip:port (private address or C2 port)."""
    return lambda e: (
        f"Private address: {ip}:{port} " in e.get("description", "")
        or f"port {port} to {ip}" in e.get("description", "")
    )


def test_allowlist_lan_host_not_flagged(test_workspace, coi_binary):
    with fake_lan("192.168.204", hosts=(20, 21, 22), ports=(443, 8080, 4444)) as (
        redmine,
        portless,
        other,
    ):
        config = f"""
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1/32"]
allowed_ports = [443, 8080]

[[network.hosts]]
ip = "{redmine}"
hostnames = ["redmine.lan"]
ports = [443, 8080]

[[network.hosts]]
ip = "{portless}"
hostnames = ["portless.lan"]

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000

[monitoring.nft]
enabled = true
"""
        with monitored_shell(test_workspace, coi_binary, SLOT, config) as (
            container_name,
            holders,
        ):
            # The configured service, on both of its ports, held open while the
            # controls below are detected.
            for port in (443, 8080):
                holders.append(hold_connect(container_name, "redmine.lan", port))
                assert_established(container_name, holders[-1], redmine, port)

            # Firewall-permitted through allowed_ports, but not on an explicit
            # port: both monitors reach the C2-port check and flag it.
            holders.append(hold_connect(container_name, "portless.lan", 8080))
            assert_established(container_name, holders[-1], portless, 8080)
            for monitor, match in (("process", _proc_c2), ("nft", _nft_c2)):
                assert wait_for_threats(container_name, match(portless, 8080), nft=True), (
                    f"the {monitor} monitor must flag {portless}:8080 as a C2 port; "
                    f"threat events: {get_threat_events(container_name, nft=True)}"
                )

            # Controls, as UDP: the firewall rejects them, and a connected UDP
            # socket stays in /proc/net/udp for the process monitor.
            holders.append(hold_connect(container_name, redmine, 4444, proto="udp"))
            holders.append(hold_connect(container_name, other, 8080, proto="udp"))
            for ip, port in ((redmine, 4444), (other, 8080)):
                for monitor, match in (("process", _proc_threat), ("nft", _nft_threat)):
                    assert wait_for_threats(container_name, match(ip, port), nft=True), (
                        f"the {monitor} monitor must flag {ip}:{port}; "
                        f"threat events: {get_threat_events(container_name, nft=True)}"
                    )

            # Both monitors polled while the service connections were open.
            flagged = [
                e
                for e in get_threat_events(container_name, nft=True)
                if any(
                    _proc_threat(redmine, port)(e) or _nft_threat(redmine, port)(e)
                    for port in (443, 8080)
                )
            ]
            assert not flagged, f"redmine.lan:443 and :8080 must not be flagged, got: {flagged}"
