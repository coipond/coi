"""
Test for coi shell - per-container drops hold at the host veth.

Tests that:
1. In restricted and allowlist mode, root inside the container who re-enables
   IPv6 reaches nothing over IPv6: not the host itself, not a host routed
   beyond the bridge (ping -6 and TCP connect), and the coi6-<name> netdev
   chain's drop counter rises on every attempt, so each drop is coi's and not a
   missing route.
2. During a restart, a boot-time service that tries from the first instant of
   boot to reach the host and a routed private host, over IPv4 and over IPv6
   it re-enables itself, never gets through before (or after) the mode's rules
   are in place (restricted mode refuses all of them).
3. Control, in the same run: with the coi6 chain swapped for the old
   forward-hook `iifname <veth>` rule, the host attempt of 1 gets through and
   that rule counts no packets, so the test catches that regression.

The bridge on the test host may route no IPv6, so the test gives the bridge and
the container static IPv6 addresses and a route itself, and puts the "outside"
host in a network namespace on the test host, routed by the host. It never
skips.
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
OUT_NS = "coi-e2e-out"
OUT_HOST_IF, OUT_NS_IF = "coie2eh", "coie2eo"
OUT_GW_V4, OUT_V4 = "172.31.254.1", "172.31.254.2"
OUT_GW_V6, OUT_V6 = "fd42:c016:7e57::1", "fd42:c016:7e57::2"
OUT_PORT = 18443

# Accepts TCP on OUT_V4 and OUT_V6 at argv[1], appending each peer to argv[2].
OUT_SERVER = """
import select, socket, sys
port, log = int(sys.argv[1]), sys.argv[2]
socks = []
for fam, addr in ((socket.AF_INET, sys.argv[3]), (socket.AF_INET6, sys.argv[4])):
    s = socket.socket(fam)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(64)
    socks.append(s)
open(log, "w").close()
while True:
    for s in select.select(socks, [], [])[0]:
        c, peer = s.accept()
        with open(log, "a") as f:
            f.write(peer[0] + "\\n")
        c.close()
"""


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


def _sudo(*argv, check=True, input=None):
    r = subprocess.run(
        ["sudo", "-n", *argv], capture_output=True, text=True, timeout=30, input=input
    )
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


@contextlib.contextmanager
def _outside_host(bridge):
    """A host beyond the bridge: a netns behind a routed veth on the test host.

    Yields (port, peers), where peers() lists the addresses that connected to
    OUT_V4/OUT_V6 on port. Restores forwarding and removes everything after.
    """
    fwd = "net.ipv6.conf.all.forwarding"
    old_fwd = _sudo("sysctl", "-n", fwd).stdout.strip()
    allow = [
        ("iptables", "FORWARD", "-i", bridge, "-o", OUT_HOST_IF, "-j", "ACCEPT"),
        ("iptables", "FORWARD", "-i", OUT_HOST_IF, "-o", bridge, "-j", "ACCEPT"),
        ("ip6tables", "FORWARD", "-i", bridge, "-o", OUT_HOST_IF, "-j", "ACCEPT"),
        ("ip6tables", "FORWARD", "-i", OUT_HOST_IF, "-o", bridge, "-j", "ACCEPT"),
    ]
    fd, log = tempfile.mkstemp(prefix="coi-e2e-out-")
    os.close(fd)
    os.chmod(log, 0o666)
    port = OUT_PORT
    server = None
    try:
        _sudo("ip", "netns", "add", OUT_NS)
        _sudo("ip", "link", "add", OUT_HOST_IF, "type", "veth", "peer", "name", OUT_NS_IF)
        _sudo("ip", "link", "set", OUT_NS_IF, "netns", OUT_NS)
        _sudo("ip", "addr", "add", f"{OUT_GW_V4}/24", "dev", OUT_HOST_IF)
        _sudo("ip", "-6", "addr", "add", f"{OUT_GW_V6}/64", "dev", OUT_HOST_IF, "nodad")
        _sudo("ip", "link", "set", OUT_HOST_IF, "up")
        ns = ("ip", "netns", "exec", OUT_NS)
        _sudo(*ns, "ip", "link", "set", "lo", "up")
        _sudo(*ns, "ip", "addr", "add", f"{OUT_V4}/24", "dev", OUT_NS_IF)
        _sudo(*ns, "ip", "-6", "addr", "add", f"{OUT_V6}/64", "dev", OUT_NS_IF, "nodad")
        _sudo(*ns, "ip", "link", "set", OUT_NS_IF, "up")
        _sudo(*ns, "ip", "route", "add", "default", "via", OUT_GW_V4)
        _sudo(*ns, "ip", "-6", "route", "add", "default", "via", OUT_GW_V6)
        _sudo("sysctl", "-w", f"{fwd}=1")
        for tool, chain, *rule in allow:
            _sudo(tool, "-I", chain, *rule, check=False)
        server = subprocess.Popen(
            ["sudo", "-n", *ns, "python3", "-I", "-c", OUT_SERVER, str(port), log, OUT_V4, OUT_V6],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10
        while (
            not os.path.exists(log)
            or _sudo(*ns, "ss", "-ltn", check=False).stdout.count(f":{port} ") < 2
        ):
            assert time.monotonic() < deadline, "outside listener did not come up"
            time.sleep(0.2)

        def peers():
            with open(log) as f:
                return f.read().split()

        yield port, peers
    finally:
        if server is not None:
            pids = _sudo("ip", "netns", "pids", OUT_NS, check=False).stdout.split()
            if pids:
                _sudo("kill", *pids, check=False)
            server.wait(timeout=10)
        for tool, chain, *rule in allow:
            _sudo(tool, "-D", chain, *rule, check=False)
        _sudo("sysctl", "-w", f"{fwd}={old_fwd}", check=False)
        _sudo("ip", "link", "del", OUT_HOST_IF, check=False)
        _sudo("ip", "netns", "del", OUT_NS, check=False)
        os.unlink(log)


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

    with _bridge_v6(bridge), _outside_host(bridge) as (out_port, out_peers):
        port = _free_port(socket.AF_INET6, HOST_V6)
        with _counting_listener(socket.AF_INET6, HOST_V6, port) as peers:
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
                "ping outside": f"ping -6 -c 3 -W 2 {OUT_V6}",
                "tcp outside": (
                    f"curl -s -o /dev/null --connect-timeout 3 http://[{OUT_V6}]:{out_port}/"
                ),
            }
            for what, cmd in attempts.items():
                before = _drop_packets(chain)
                rc, out = exec_in(coi_binary, name, cmd, timeout=30)
                after = _drop_packets(chain)
                assert rc != 0, f"IPv6 {what} got through with IPv6 re-enabled: {out}"
                assert after > before, (
                    f"{chain} counted no drops for {what} ({before} -> {after}):"
                    " the traffic failed for another reason"
                )
            assert peers == [], f"host listener accepted IPv6 connections: {peers}"
            assert out_peers() == [], f"outside host accepted IPv6 connections: {out_peers()}"

            # Control: with the coi6 chain swapped for the old forward-hook
            # rule, the same host attempt gets through and the old rule counts
            # nothing, so the assertions above catch that regression.
            veth = _veth(name)
            _sudo("nft", "delete", "chain", "netdev", "coi", chain)
            _sudo(
                "nft",
                "-f",
                "-",
                input=(
                    "add table ip6 coi\n"
                    "add chain ip6 coi forward"
                    " { type filter hook forward priority 10 ; policy accept ; }\n"
                    f'add rule ip6 coi forward iifname "{veth}" counter drop comment "{chain}"\n'
                ),
            )
            rc, out = exec_in(coi_binary, name, attempts["tcp host"], timeout=30)
            old = _sudo("nft", "list", "chain", "ip6", "coi", "forward").stdout
            assert peers, f"control: the host attempt should get through the old rule: {out}"
            assert re.search(rf"counter packets 0 bytes 0 drop comment \"{chain}\"", old), (
                f"control: the old forward-hook rule should match nothing:\n{old}"
            )


def test_boot_service_never_gets_out_before_rules(coi_binary, workspace_dir, cleanup_containers):
    toml = '[network]\nmode = "restricted"\n'
    name, env = _launch(coi_binary, workspace_dir, toml, persistent=True)
    rc, gw = exec_in(coi_binary, name, "ip -4 route show default | awk '{print $3; exit}'")
    gateway = gw.strip()
    assert rc == 0 and gateway, f"no IPv4 gateway in the container: {gw}"
    port = _free_port(socket.AF_INET, gateway)
    v6_port = port  # HOST_V6 is a different address: the same port is free
    bridge = _bridge_of(_veth(name))

    # A unit that starts early in boot and, every 0.1 s for 60 s, re-enables
    # IPv6 and tries the host and the outside host over IPv4 and IPv6, logging
    # the start time of each round. The listeners count what got in.
    probe = f"""#!/bin/bash
end=$((SECONDS+60))
while [ $SECONDS -lt $end ]; do
  sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 \\
    net.ipv6.conf.eth0.disable_ipv6=0 2>/dev/null
  ip -6 addr add {CTR_V6}/64 dev eth0 nodad 2>/dev/null
  ip -6 route replace default via {HOST_V6} dev eth0 2>/dev/null
  echo "$(date +%s.%N)" >> /var/log/boot-probe.log
  for url in http://{gateway}:{port}/ http://{OUT_V4}:{OUT_PORT}/ \\
      http://[{HOST_V6}]:{v6_port}/ http://[{OUT_V6}]:{OUT_PORT}/; do
    curl -s -o /dev/null --connect-timeout 1 "$url"
  done
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

    with (
        _bridge_v6(bridge),
        _outside_host(bridge) as (_, out_peers),
        _counting_listener(socket.AF_INET, gateway, port) as peers,
        _counting_listener(socket.AF_INET6, HOST_V6, v6_port) as v6_peers,
    ):
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
            lines = [ln.split() for ln in log.splitlines() if re.match(r"^\d+\.\d+$", ln)]
            if lines and float(lines[-1][0]) > rules_in_place + 3:
                break
            time.sleep(0.5)

        assert lines, "boot probe logged no attempts"
        assert float(lines[0][0]) < rules_in_place, (
            f"boot probe started only after the rules were in place ({lines[0][0]} >= {rules_in_place})"
        )
        assert float(lines[-1][0]) > rules_in_place + 3, "boot probe stopped before the deadline"
        assert peers == [] and v6_peers == [], (
            f"restricted container reached the host during boot: IPv4 {peers}, IPv6 {v6_peers}"
        )
        assert out_peers() == [], (
            f"restricted container reached the outside host during boot: {out_peers()}"
        )
