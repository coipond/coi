"""
Test for coi shell - per-container drops hold at the host veth.

Tests that:
1. In restricted and allowlist mode, root inside the container who re-enables
   IPv6 reaches nothing over IPv6: not the host itself, not a host beyond the
   bridge (ping -6 and TCP connect), and the coi6-<name> netdev chain's drop
   counter is above zero, so the drop is coi's and not a missing route.
2. During a restart, a boot-time service that connects to the host from the
   first instant of boot never gets through before the mode's rules are in
   place (restricted mode refuses the host, so it must never get through).

The bridge on the test host may route no IPv6, so the test gives the bridge and
the container static IPv6 addresses and a route itself. It never skips.
"""

import contextlib
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time

import pytest

from support.helpers import exec_in, start_background_shell

HOST_V6 = "fd42:c015:7e57::1"
CTR_V6 = "fd42:c015:7e57::2"
OUTSIDE_V6 = "2606:4700:4700::1111"


def _instance_state(name):
    r = subprocess.run(
        ["incus", "query", f"/1.0/instances/{name}/state"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r.returncode == 0, f"incus query state failed: {r.stderr}"
    return json.loads(r.stdout)


def _veth(name):
    return (_instance_state(name).get("network") or {}).get("eth0", {}).get("host_name", "")


def _bridge_of(veth):
    out = subprocess.run(
        ["ip", "-o", "link", "show", veth], capture_output=True, text=True, timeout=10
    ).stdout
    m = re.search(r"\bmaster (\S+)", out)
    assert m, f"veth {veth} has no bridge master: {out}"
    return m.group(1)


def _sudo(*argv, check=True):
    r = subprocess.run(["sudo", "-n", *argv], capture_output=True, text=True, timeout=30)
    if check:
        assert r.returncode == 0, f"{' '.join(argv)} failed: {r.stderr}"
    return r


def _drop_packets(chain):
    """Packets counted by the drop rule of netdev coi chain, or -1 if absent."""
    r = _sudo("nft", "list", "chain", "netdev", "coi", chain, check=False)
    m = re.search(r"counter packets (\d+) bytes \d+ drop", r.stdout)
    return int(m.group(1)) if m else -1


@contextlib.contextmanager
def _bridge_v6(bridge):
    """Give the bridge HOST_V6, restoring its IPv6 state afterwards."""
    key = f"net.ipv6.conf.{bridge}.disable_ipv6"
    old = _sudo("sysctl", "-n", key).stdout.strip()
    _sudo("sysctl", "-w", f"{key}=0")
    added = (
        _sudo(
            "ip", "-6", "addr", "add", f"{HOST_V6}/64", "dev", bridge, "nodad", check=False
        ).returncode
        == 0
    )
    try:
        yield
    finally:
        if added:
            _sudo("ip", "-6", "addr", "del", f"{HOST_V6}/64", "dev", bridge, check=False)
        _sudo("sysctl", "-w", f"{key}={old}", check=False)


@contextlib.contextmanager
def _counting_listener(family, addr, port):
    """A TCP listener on the host; yields the list of peer addresses it accepted."""
    peers = []
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, port))
    srv.listen(64)
    srv.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, peer = srv.accept()
            except (TimeoutError, OSError):
                continue
            peers.append(peer[0])
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield peers
    finally:
        stop.set()
        t.join(timeout=5)
        srv.close()


def _free_port(family, addr):
    with socket.socket(family) as s:
        s.bind((addr, 0))
        return s.getsockname()[1]


def _launch(coi_binary, workspace_dir, network_toml, persistent=False):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        if persistent:
            f.write("[container]\npersistent = true\n")
        f.write(network_toml)
    env = {**os.environ, "COI_CONFIG": f.name}
    name, _ = start_background_shell(coi_binary, workspace_dir, env, debug=False)
    return name, env


@pytest.mark.parametrize(
    "network_toml",
    [
        '[network]\nmode = "restricted"\n',
        '[network]\nmode = "allowlist"\nallowed_domains = ["1.1.1.1:443"]\n',
    ],
    ids=["restricted", "allowlist"],
)
def test_reenabled_ipv6_is_dropped_at_the_veth(
    coi_binary, workspace_dir, cleanup_containers, network_toml
):
    name, _ = _launch(coi_binary, workspace_dir, network_toml)
    chain = f"coi6-{name}"
    deadline = time.monotonic() + 30
    while _drop_packets(chain) < 0 and time.monotonic() < deadline:
        time.sleep(0.5)
    assert _drop_packets(chain) >= 0, f"netdev chain {chain} not installed"
    bridge = _bridge_of(_veth(name))

    with _bridge_v6(bridge):
        port = _free_port(socket.AF_INET6, HOST_V6)
        with _counting_listener(socket.AF_INET6, HOST_V6, port) as peers:
            before = _drop_packets(chain)
            rc, out = exec_in(
                coi_binary,
                name,
                "sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0"
                " net.ipv6.conf.eth0.disable_ipv6=0"
                f" && ip -6 addr add {CTR_V6}/64 dev eth0 nodad"
                f" && ip -6 route replace default via {HOST_V6} dev eth0",
            )
            assert rc == 0, f"root could not re-enable IPv6 in the container: {out}"

            attempts = {
                "ping host": f"ping -6 -c 3 -W 2 {HOST_V6}",
                "tcp host": f"curl -s -o /dev/null --connect-timeout 3 http://[{HOST_V6}]:{port}/",
                "ping outside": f"ping -6 -c 3 -W 2 {OUTSIDE_V6}",
                "tcp outside": f"curl -s -o /dev/null --connect-timeout 3 http://[{OUTSIDE_V6}]:80/",
            }
            for what, cmd in attempts.items():
                rc, out = exec_in(coi_binary, name, cmd, timeout=30)
                assert rc != 0, f"IPv6 {what} got through with IPv6 re-enabled: {out}"
            assert peers == [], f"host listener accepted IPv6 connections: {peers}"

        after = _drop_packets(chain)
        assert after > before, (
            f"{chain} counted no drops ({before} -> {after}): the traffic failed for another reason"
        )


def test_boot_service_never_reaches_host_before_rules(
    coi_binary, workspace_dir, cleanup_containers
):
    toml = '[network]\nmode = "restricted"\n'
    name, env = _launch(coi_binary, workspace_dir, toml, persistent=True)
    rc, gw = exec_in(coi_binary, name, "ip -4 route show default | awk '{print $3; exit}'")
    gateway = gw.strip()
    assert rc == 0 and gateway, f"no IPv4 gateway in the container: {gw}"
    port = _free_port(socket.AF_INET, gateway)

    # A unit that starts early in boot and connects to the host every 0.1 s for
    # 60 s, logging the time of each attempt. The listener counts what got in.
    probe = f"""#!/bin/bash
end=$((SECONDS+60))
while [ $SECONDS -lt $end ]; do
  curl -s -o /dev/null --connect-timeout 1 http://{gateway}:{port}/
  rc=$?
  echo "$(date +%s.%N) $rc" >> /var/log/boot-probe.log
  sleep 0.1
done
"""
    unit = """[Unit]
Description=boot egress probe
DefaultDependencies=no

[Service]
Type=simple
ExecStart=/usr/local/bin/boot-probe

[Install]
WantedBy=sysinit.target
"""
    rc, out = exec_in(
        coi_binary,
        name,
        f"cat > /usr/local/bin/boot-probe <<'EOF'\n{probe}EOF\n"
        "chmod 755 /usr/local/bin/boot-probe\n"
        f"cat > /etc/systemd/system/boot-probe.service <<'EOF'\n{unit}EOF\n"
        "systemctl enable boot-probe.service && rm -f /var/log/boot-probe.log",
    )
    assert rc == 0, f"could not install the boot probe: {out}"

    with _counting_listener(socket.AF_INET, gateway, port) as peers:
        stop = subprocess.run(
            [coi_binary, "container", "stop", name, "--force"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert stop.returncode == 0, f"container stop failed: {stop.stderr}"
        start = subprocess.run(
            [coi_binary, "container", "start", name],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        assert start.returncode == 0, f"container start failed: {start.stderr}"
        rules_in_place = time.time()

        # The probe must have run both before and well after the rules landed.
        deadline = time.monotonic() + 60
        lines = []
        while time.monotonic() < deadline:
            _, log = exec_in(coi_binary, name, "cat /var/log/boot-probe.log 2>/dev/null || true")
            lines = [ln.split() for ln in log.splitlines() if re.match(r"^\d+\.\d+ \d+$", ln)]
            if lines and float(lines[-1][0]) > rules_in_place + 3:
                break
            time.sleep(0.5)

        assert lines, "boot probe logged no attempts"
        assert float(lines[0][0]) < rules_in_place, (
            f"boot probe started only after the rules were in place ({lines[0][0]} >= {rules_in_place})"
        )
        assert float(lines[-1][0]) > rules_in_place + 3, "boot probe stopped before the deadline"
        assert peers == [], (
            f"restricted container reached the host during boot; listener saw {peers}"
        )
