"""
Test for coi clean --orphans - keeps the host veth of a non-coi container.

Tests that:
1. Add a p2p NIC to a running foreign container (its host veth has no
   bridge master, like a routed NIC's)
2. Run coi clean --orphans --force
3. Verify the host veth still exists and the foreign container keeps its NIC
"""

import os
import subprocess

from support.helpers import container_config_get


def test_clean_orphans_keeps_foreign_p2p_veth(coi_binary, foreign_containers):
    name = foreign_containers["running"]

    result = subprocess.run(
        ["incus", "config", "device", "add", name, "eth1", "nic", "nictype=p2p"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Adding a p2p NIC should succeed. stderr: {result.stderr}"

    host_veth = container_config_get(name, "volatile.eth1.host_name")
    assert host_veth, "p2p NIC should have a host veth"
    assert os.path.exists(f"/sys/class/net/{host_veth}"), f"{host_veth} should exist"
    assert not os.path.exists(f"/sys/class/net/{host_veth}/master"), (
        f"{host_veth} should have no bridge master"
    )

    result = subprocess.run(
        [coi_binary, "clean", "--orphans", "--force"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Clean --orphans should succeed. stderr: {result.stderr}"
    combined_output = result.stdout + result.stderr
    assert host_veth not in combined_output, (
        f"clean --orphans must not name {host_veth}:\n{combined_output}"
    )

    assert os.path.exists(f"/sys/class/net/{host_veth}"), (
        f"coi clean --orphans deleted {name}'s host veth {host_veth}"
    )
