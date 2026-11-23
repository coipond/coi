"""
Test for coi shell - the boot block lets nothing out before the mode's rules.

Tests that:
1. During a restart of a restricted container, a boot-time service that tries
   from the first instant of boot to reach the host and a routed private host,
   over IPv4 and over IPv6 it re-enables itself, never gets through, before or
   after the mode's rules are in place (restricted mode refuses all of them).
2. The service ran both before and after the rules were in place.

The bridge on the test host may route no IPv6, so the test gives the bridge and
the container static IPv6 addresses and a route itself, and puts the "outside"
host in a network namespace on the test host, routed by the host. It never
skips.
"""

import re
import socket
import subprocess
import time

from support.helpers import (
    BRIDGE_V6,
    CTR_V6,
    OUT_PORT,
    OUT_V4,
    OUT_V6,
    bridge_v6,
    counting_listener,
    exec_in,
    free_host_port,
    host_veth,
    launch_with_network,
    outside_host,
    veth_bridge,
)


def test_boot_service_never_gets_out_before_rules(coi_binary, workspace_dir, cleanup_containers):
    toml = '[network]\nmode = "restricted"\n'
    name, env = launch_with_network(coi_binary, workspace_dir, toml, persistent=True)
    rc, gw = exec_in(coi_binary, name, "ip -4 route show default | awk '{print $3; exit}'")
    gateway = gw.strip()
    assert rc == 0 and gateway, f"no IPv4 gateway in the container: {gw}"
    port = free_host_port(gateway, family=socket.AF_INET)
    v6_port = port  # BRIDGE_V6 is a different address: the same port is free
    bridge = veth_bridge(host_veth(name))

    # The probe logs each round before its attempts: dropped attempts make a
    # round take seconds, and the first log line must predate the rules.
    probe = f"""#!/bin/bash
end=$((SECONDS+60))
while [ $SECONDS -lt $end ]; do
  sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 \\
    net.ipv6.conf.eth0.disable_ipv6=0 2>/dev/null
  ip -6 addr add {CTR_V6}/64 dev eth0 nodad 2>/dev/null
  ip -6 route replace default via {BRIDGE_V6} dev eth0 2>/dev/null
  echo "$(date +%s.%N)" >> /var/log/boot-probe.log
  for url in http://{gateway}:{port}/ http://{OUT_V4}:{OUT_PORT}/ \\
      http://[{BRIDGE_V6}]:{v6_port}/ http://[{OUT_V6}]:{OUT_PORT}/; do
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
        bridge_v6(bridge),
        outside_host(bridge) as (_, out_peers),
        counting_listener(socket.AF_INET, gateway, port) as peers,
        counting_listener(socket.AF_INET6, BRIDGE_V6, v6_port) as v6_peers,
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
