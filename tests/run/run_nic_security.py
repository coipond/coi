"""
Test that `coi run` hardens the bridge NIC against egress-isolation bypass.

`coi shell` applied EnableNICSecurity (security.ipv4_filtering / mac_filtering /
port_isolation on eth0) but `coi run` did not, so a restricted/allowlisted run
could spoof its source IP/MAC to dodge the saddr-keyed nft rules. This asserts
`coi run` now sets those keys on eth0 (#726 follow-up, same class as #373).
"""

import subprocess

from support.helpers import (
    calculate_container_name,
    container_device_get,
    write_workspace_container_config,
)


def test_run_enables_nic_security(coi_binary, cleanup_containers, workspace_dir):
    """coi run must set the eth0 anti-spoof / port-isolation keys before boot."""
    slot = 7
    container_name = calculate_container_name(workspace_dir, slot)
    # Persistent so the container survives the run and its device config is
    # inspectable from the host afterwards.
    write_workspace_container_config(workspace_dir, persistent=True)

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--slot", str(slot), "--", "true"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, f"coi run should succeed. stderr: {result.stderr}"

    try:
        for key in ("security.ipv4_filtering", "security.mac_filtering", "security.port_isolation"):
            val = container_device_get(container_name, "eth0", key)
            assert val is not None, f"could not read eth0 {key}"
            assert val == "true", f"eth0 {key} should be 'true' after coi run, got '{val}'"
    finally:
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
            check=False,
        )
