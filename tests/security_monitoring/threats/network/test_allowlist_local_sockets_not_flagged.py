"""Allowlist mode: sockets that cannot leave the container must not be flagged.

The resolver stub (127.0.0.53), services on other loopback addresses (127.0.0.2,
127.0.1.1), a bound udp6 socket on ::, and a connected UDP socket to the bridge
gateway's DNS port are all local or blocked by the firewall. Another port on
the gateway must still be flagged, and a name not in /etc/hosts must fail at
once."""

import subprocess
import time
from pathlib import Path

from support.helpers import exec_in
from support.monitoring import (
    cleanup_container,
    get_container_state,
    get_threat_events,
    start_shell,
)

SLOT = 72

# No "socket.socket" in these scripts: the process monitor flags python3 with
# it as a reverse shell and pauses the container.
GATEWAY = """
import struct, time
from socket import AF_INET, AF_INET6, SOCK_DGRAM, create_connection, inet_ntoa, socket

def gateway():
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            fields = line.split()
            if fields[1] == "00000000":
                return inet_ntoa(struct.pack("<L", int(fields[2], 16)))
"""

HOLD = (
    GATEWAY
    + """
held = []
stub = socket(AF_INET, SOCK_DGRAM)
stub.connect(("127.0.0.53", 53))
held.append(stub)
bound6 = socket(AF_INET6, SOCK_DGRAM)
bound6.bind(("::", 0))
held.append(bound6)
for addr in ("127.0.0.2", "127.0.1.1"):
    srv = socket()
    srv.bind((addr, 0))
    srv.listen(1)
    held.append(srv)
    held.append(create_connection(srv.getsockname()))
dns = socket(AF_INET, SOCK_DGRAM)
dns.connect((gateway(), 53))
held.append(dns)
time.sleep(60)
"""
)

HOLD_GATEWAY_OTHER_PORT = (
    GATEWAY
    + """
s = socket(AF_INET, SOCK_DGRAM)
s.connect((gateway(), 5353))
time.sleep(60)
"""
)


def _hold(container_name, script):
    return subprocess.Popen(
        ["incus", "exec", container_name, "--", "python3", "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_allowlist_local_sockets_not_flagged(test_workspace, coi_binary):
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1/32"]

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
        _, nss = exec_in(coi_binary, container_name, "grep '^hosts:' /etc/nsswitch.conf")
        assert nss.split()[1:3] == ["files", "[!SUCCESS=return]"], (
            f"allowlist mode must look names up in /etc/hosts only: {nss}"
        )
        start = time.monotonic()
        rc, lookup = exec_in(coi_binary, container_name, "getent hosts example.org", timeout=15)
        elapsed = time.monotonic() - start
        assert rc != 0, f"example.org is not in /etc/hosts: {lookup}"
        assert elapsed < 5, f"an unknown name must fail at once, took {elapsed:.1f}s"

        holders.append(_hold(container_name, HOLD))
        time.sleep(15)
        assert get_container_state(container_name) == "Running", (
            "local resolver and loopback sockets must not pause the container; "
            f"threat events: {get_threat_events(container_name)}"
        )
        flagged = [e for e in get_threat_events(container_name) if e.get("category") == "network"]
        assert not flagged, f"no local socket may be flagged, got: {flagged}"

        # Positive control: another port on the gateway is still flagged.
        holders.append(_hold(container_name, HOLD_GATEWAY_OTHER_PORT))
        threats = []
        deadline = time.monotonic() + 45
        while not threats and time.monotonic() < deadline:
            threats = [
                e for e in get_threat_events(container_name) if ":5353" in e.get("description", "")
            ]
            time.sleep(2)
        assert threats, "a socket to another port on the gateway must still be flagged"
    finally:
        for h in holders:
            h.terminate()
        proc.terminate()
        cleanup_container(container_name, coi_binary)
        if backup is not None:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
