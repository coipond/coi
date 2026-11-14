"""Allowlist mode: a connection opened while its address was allowlisted must
not be flagged after the address leaves the dynamic nft set. The firewall keeps
the flow open (ct state established), so it is not a violation. A new socket to
the same address must still be flagged.

The test empties the dynamic sets instead of waiting for the element timeout
(TTL + refresh interval + 10 minutes)."""

import subprocess
import time
from pathlib import Path

from support.helpers import container_ipv4, exec_in
from support.monitoring import (
    cleanup_container,
    get_container_state,
    get_threat_events,
    hold_script,
    poll_network_threats,
    start_shell,
)

SLOT = 74

# One keep-alive HTTP connection, no reconnect: the flow must stay the same.
HOLD_HTTP = """
import time
from http.client import HTTPConnection
conn = HTTPConnection("example.com", 80, timeout=10)
conn.auto_open = 0
conn.connect()
end = time.monotonic() + 90
while time.monotonic() < end:
    conn.request("HEAD", "/", headers={"Connection": "keep-alive"})
    conn.getresponse().read()
    time.sleep(2)
"""

HOLD_UDP = """
import sys, time
from socket import AF_INET, SOCK_DGRAM, socket
s = socket(AF_INET, SOCK_DGRAM)
s.connect((sys.argv[1], 80))
time.sleep(60)
"""


def _peer(coi_binary, container_name):
    rc, out = exec_in(coi_binary, container_name, "ss -Htn state established '( dport = :80 )'")
    assert rc == 0, f"ss failed: {out}"
    peers = [line.split()[-1].rsplit(":", 1)[0] for line in out.splitlines() if line.strip()]
    assert len(peers) == 1, f"want one held connection, got: {out}"
    return peers[0]


def test_allowlist_expired_flow_not_flagged(test_workspace, coi_binary):
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1/32", "example.com"]
refresh_interval_minutes = 30

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
        holders.append(hold_script(container_name, HOLD_HTTP))
        time.sleep(5)
        assert holders[0].poll() is None, "the keep-alive connection must open"
        peer = _peer(coi_binary, container_name)

        # Expire every dynamic element, as the timeout would.
        ident = container_ipv4(container_name).replace(".", "_")
        for prefix in ("coi_d_", "coi_dp_"):
            subprocess.run(
                ["sudo", "-n", "nft", "flush", "set", "ip", "coi", prefix + ident],
                check=True,
                timeout=15,
            )

        time.sleep(15)
        assert holders[0].poll() is None, "the firewall must keep the held flow open"
        assert get_container_state(container_name) == "Running", (
            "a flow opened while allowlisted must not pause the container; "
            f"threat events: {get_threat_events(container_name)}"
        )
        flagged = [e for e in get_threat_events(container_name) if peer in e.get("description", "")]
        assert not flagged, f"the held flow to {peer} must not be flagged, got: {flagged}"

        # Positive control: a new socket to the expired address is flagged.
        holders.append(hold_script(container_name, HOLD_UDP, peer))
        threats = poll_network_threats(container_name, match=f"{peer}:80")
        assert threats, "a new socket to an expired address must still be flagged"
    finally:
        for h in holders:
            h.terminate()
        proc.terminate()
        cleanup_container(container_name, coi_binary)
        if backup is not None:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
