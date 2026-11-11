"""
Test for coi network isolation - adds no firewall rules for non-coi containers.

Tests that:
1. Start foreign containers (running, stopped, and one whose name holds "coi-"
   but does not start with it) with plain incus
2. Start a coi shell in the background in restricted mode
3. Verify coi's firewall rules exist for its container and none name a
   foreign container's IP
4. Shut the coi container down
5. Verify the foreign containers keep their status, config, profiles,
   devices and snapshots, and the running ones keep their IP
"""

import pathlib
import re
import subprocess
import time

from support.helpers import (
    calculate_container_name,
    container_ipv4,
    foreign_container_state,
    wait_for_firewall_rules,
)


def _ip_pattern(ip):
    return re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.])")


def test_network_spares_foreign_containers(
    coi_binary, workspace_dir, cleanup_containers, foreign_containers
):
    container_name = calculate_container_name(workspace_dir, 1)
    foreign = list(foreign_containers.values())
    running_foreign = [foreign_containers["running"], foreign_containers["lookalike"]]

    foreign_ips = {}
    for name in running_foreign:
        for _ in range(30):
            ip = container_ipv4(name)
            if ip:
                break
            time.sleep(1)
        assert ip, f"Foreign container {name} should get an IPv4 address"
        foreign_ips[name] = ip

    before = foreign_container_state(foreign)

    config_dir = pathlib.Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text('[network]\nmode = "restricted"\n')

    result = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Shell should start successfully. stderr: {result.stderr}"
    assert wait_for_firewall_rules(container_name), "coi firewall rules should be applied"

    ruleset = subprocess.run(
        ["sudo", "-n", "nft", "list", "ruleset"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert ruleset.returncode == 0, f"nft list ruleset failed: {ruleset.stderr}"
    for name, ip in foreign_ips.items():
        assert not _ip_pattern(ip).search(ruleset.stdout), (
            f"nft ruleset must not hold rules for foreign container {name} ({ip})"
        )

    result = subprocess.run(
        [coi_binary, "shutdown", "--force", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Shutdown should succeed. stderr: {result.stderr}"

    assert foreign_container_state(foreign) == before
    for name, ip in foreign_ips.items():
        assert container_ipv4(name) == ip, f"Foreign container {name} should keep its IP"
