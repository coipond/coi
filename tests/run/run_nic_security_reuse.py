"""
Test for coi run - a reused persistent container gets NIC anti-spoofing back.

A persistent container created by an older coi has no anti-spoofing keys on
eth0, so in-container root could send from a second source IP that no
saddr-keyed nft rule matches. Removing coi's eth0 override while the container
is stopped gives the same state: eth0 comes from the profile without the keys.

Tests that:
1. A restricted persistent coi run sets the eth0 keys
2. With the override removed, the next coi run reuses the container and sets
   them again before the start
"""

import subprocess
from pathlib import Path

from support.helpers import calculate_container_name, container_device_get

NIC_KEYS = ("security.ipv4_filtering", "security.mac_filtering", "security.port_isolation")


def _run(coi_binary, workspace_dir):
    return subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "true"],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
    )


def test_run_reuse_restores_nic_security(coi_binary, workspace_dir, cleanup_containers):
    """A reused restricted container without the eth0 keys gets them on restart."""
    container_name = calculate_container_name(workspace_dir, 1)
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        '\n[container]\npersistent = true\n\n[network]\nmode = "restricted"\n'
    )

    first = _run(coi_binary, workspace_dir)
    assert first.returncode == 0, f"first coi run should succeed. stderr: {first.stderr}"
    for key in NIC_KEYS:
        assert container_device_get(container_name, "eth0", key) == "true", (
            f"eth0 {key} should be 'true' after the first run"
        )

    # The persistent run leaves the container stopped; drop coi's override.
    removed = subprocess.run(
        ["incus", "config", "device", "remove", container_name, "eth0"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert removed.returncode == 0, f"could not remove the eth0 override: {removed.stderr}"
    assert container_device_get(container_name, "eth0", "security.ipv4_filtering") != "true", (
        "eth0 should have no anti-spoofing once the override is removed"
    )

    second = _run(coi_binary, workspace_dir)
    assert second.returncode == 0, f"reused coi run should succeed. stderr: {second.stderr}"
    for key in NIC_KEYS:
        val = container_device_get(container_name, "eth0", key)
        assert val == "true", f"eth0 {key} should be 'true' after the reuse, got {val!r}"
