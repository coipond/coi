"""
Test for coi shutdown --all - leaves non-coi containers alone.

Tests that:
1. Launch a coi container next to foreign containers (running, stopped, and
   one whose name holds "coi-" but does not start with it)
2. Shut down all with --all --force
3. Verify the coi container is deleted
4. Verify the foreign containers' status, config, profiles, devices and
   snapshots, and the host profiles, networks and pools, are unchanged
"""

import subprocess

from support.helpers import (
    calculate_container_name,
    foreign_container_state,
    incus_host_state,
)


def test_shutdown_all_spares_foreign_containers(
    coi_binary, cleanup_containers, workspace_dir, foreign_containers
):
    container_name = calculate_container_name(workspace_dir, 1)
    foreign = list(foreign_containers.values())

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    before = foreign_container_state(foreign)
    host_before = incus_host_state()
    assert sorted(before) == sorted(foreign), f"Foreign containers missing: {before}"

    result = subprocess.run(
        [coi_binary, "shutdown", "--all", "--force"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, f"Shutdown --all should succeed. stderr: {result.stderr}"

    combined_output = result.stdout + result.stderr
    for name in foreign:
        assert name not in combined_output, (
            f"shutdown --all must not name {name}:\n{combined_output}"
        )

    result = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0, (
        f"Container {container_name} should not exist after shutdown --all"
    )

    assert foreign_container_state(foreign) == before
    assert incus_host_state() == host_before, (
        "coi must not change Incus profiles, networks or pools"
    )
