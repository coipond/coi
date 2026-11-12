"""
Test for coi run - a restricted launch with [limits] applies every launch setting.

Tests that:
1. The kernel-surface keys and security.guestapi=false set at `incus init` are present
2. eth0 carries the three anti-spoofing / port-isolation keys
3. Both IPv6 disable sysctls are set
4. The CPU and memory limits set before first boot are present
"""

import subprocess
from pathlib import Path

from support.helpers import (
    calculate_container_name,
    container_config_get,
    container_device_get,
)


def test_run_launch_config_restricted_limits(coi_binary, workspace_dir, cleanup_containers):
    """A persistent restricted coi run with limits keeps every launch setting."""
    container_name = calculate_container_name(workspace_dir, 1)

    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true
docker = true

[network]
mode = "restricted"

[limits.cpu]
count = "2"

[limits.memory]
limit = "2GiB"
enforce = "soft"
swap = "false"
"""
    )

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "echo", "test"],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
    )
    assert result.returncode == 0, f"coi run should succeed. stderr: {result.stderr}"

    want = {
        "security.nesting": "true",
        "security.syscalls.intercept.mknod": "true",
        "security.syscalls.intercept.setxattr": "true",
        "linux.sysctl.net.ipv4.ip_unprivileged_port_start": "0",
        "security.guestapi": "false",
        "linux.sysctl.net.ipv6.conf.all.disable_ipv6": "1",
        "linux.sysctl.net.ipv6.conf.default.disable_ipv6": "1",
        "limits.cpu": "2",
        "limits.memory": "2GiB",
        "limits.memory.enforce": "soft",
        "limits.memory.swap": "false",
    }
    got = {key: container_config_get(container_name, key) for key in want}
    assert got == want, f"instance config differs: {got}"

    nic_keys = ["security.ipv4_filtering", "security.mac_filtering", "security.port_isolation"]
    nic = {key: container_device_get(container_name, "eth0", key) for key in nic_keys}
    assert nic == dict.fromkeys(nic_keys, "true"), f"eth0 keys differ: {nic}"
