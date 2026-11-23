"""
Test for coi shell - re-enabled IPv6 is dropped at the container's host veth.

Tests that:
1. In restricted and allowlist mode, root inside the container who re-enables
   IPv6 reaches nothing over IPv6: not the host itself, not a host routed
   beyond the bridge (ping -6 and TCP connect), and the coi6-<name> netdev
   chain's drop counter rises on every attempt, so each drop is coi's and not a
   missing route.
2. Control, in the same run: with the coi6 chain swapped for the old
   forward-hook `iifname <veth>` rule, the host and outside attempts get
   through and that rule counts no packets, so the test catches that
   regression; `coi kill` then removes that old-style rule too.

The bridge on the test host may route no IPv6, so the test gives the bridge and
the container static IPv6 addresses and a route itself, and puts the "outside"
host in a network namespace on the test host, routed by the host. It never
skips.
"""

import re
import socket
import subprocess
import time

import pytest

from support.helpers import (
    BRIDGE_V6,
    CTR_V6,
    OUT_V6,
    bridge_v6,
    counting_listener,
    drop_chain_packets,
    exec_in,
    free_host_port,
    host_veth,
    launch_with_network,
    outside_host,
    sudo_run,
    veth_bridge,
)


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
    name, _ = launch_with_network(coi_binary, workspace_dir, network_toml)
    chain = f"coi6-{name}"
    deadline = time.monotonic() + 30
    while drop_chain_packets(chain) < 0 and time.monotonic() < deadline:
        time.sleep(0.5)
    assert drop_chain_packets(chain) >= 0, f"netdev chain {chain} not installed"
    bridge = veth_bridge(host_veth(name))

    with bridge_v6(bridge), outside_host(bridge) as (out_port, out_peers):
        port = free_host_port(socket.AF_INET6, BRIDGE_V6)
        with counting_listener(socket.AF_INET6, BRIDGE_V6, port) as peers:
            rc, out = exec_in(
                coi_binary,
                name,
                "sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0"
                " net.ipv6.conf.eth0.disable_ipv6=0"
                f" && ip -6 addr add {CTR_V6}/64 dev eth0 nodad"
                f" && ip -6 route replace default via {BRIDGE_V6} dev eth0",
            )
            assert rc == 0, f"root could not re-enable IPv6 in the container: {out}"

            attempts = {
                "ping host": f"ping -6 -c 3 -W 2 {BRIDGE_V6}",
                "tcp host": f"curl -s -o /dev/null --connect-timeout 3 http://[{BRIDGE_V6}]:{port}/",
                "ping outside": f"ping -6 -c 3 -W 2 {OUT_V6}",
                "tcp outside": (
                    f"curl -s -o /dev/null --connect-timeout 3 http://[{OUT_V6}]:{out_port}/"
                ),
            }
            for what, cmd in attempts.items():
                before = drop_chain_packets(chain)
                rc, out = exec_in(coi_binary, name, cmd, timeout=30)
                after = drop_chain_packets(chain)
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
            veth = host_veth(name)
            sudo_run("nft", "delete", "chain", "netdev", "coi", chain)
            sudo_run(
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
            old = sudo_run("nft", "list", "chain", "ip6", "coi", "forward").stdout
            assert peers, f"control: the host attempt should get through the old rule: {out}"
            assert re.search(rf"counter packets 0 bytes 0 drop comment \"{chain}\"", old), (
                f"control: the old forward-hook rule should match nothing:\n{old}"
            )
            # The runner routes to the outside host, so the outside checks
            # above (and in the boot test) are not passing by default.
            rc, out = exec_in(coi_binary, name, attempts["tcp outside"], timeout=30)
            assert out_peers(), (
                f"control: the outside attempt should get through the old rule: {out}"
            )

        # coi's cleanup also removes the rule older versions left in ip6 coi forward.
        kill = subprocess.run(
            [coi_binary, "kill", name], capture_output=True, text=True, timeout=60
        )
        assert kill.returncode == 0, f"coi kill failed: {kill.stderr}"
        deadline = time.monotonic() + 15
        while True:
            left = sudo_run("nft", "list", "chain", "ip6", "coi", "forward", check=False).stdout
            if f'comment "{chain}"' not in left or time.monotonic() > deadline:
                break
            time.sleep(0.5)
        assert f'comment "{chain}"' not in left, f"legacy rule {chain} left after kill:\n{left}"
