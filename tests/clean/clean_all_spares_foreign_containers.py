"""
Test for coi clean --all - leaves non-coi containers alone.

Tests that:
1. Launch and stop a coi container next to foreign containers (running,
   stopped, and one whose name holds "coi-" but does not start with it)
2. Run coi clean --all --force (stopped containers, orphans, pools)
3. Verify the stopped coi container is removed
4. Verify the foreign containers, the stopped one too, keep their status,
   config, profiles, devices and snapshots, and the host profiles,
   networks and pools stay unchanged
"""

import subprocess

from support.helpers import (
    calculate_container_name,
    foreign_container_state,
    incus_host_state,
)


def test_clean_all_spares_foreign_containers(
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

    result = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Container stop should succeed. stderr: {result.stderr}"

    before = foreign_container_state(foreign)
    host_before = incus_host_state()
    assert sorted(before) == sorted(foreign), f"Foreign containers missing: {before}"

    result = subprocess.run(
        [coi_binary, "clean", "--all", "--force"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Clean --all should succeed. stderr: {result.stderr}"

    combined_output = result.stdout + result.stderr
    for name in foreign:
        assert name not in combined_output, f"clean --all must not name {name}:\n{combined_output}"

    result = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0, f"Stopped coi container {container_name} should be cleaned"

    assert foreign_container_state(foreign) == before
    assert incus_host_state() == host_before, (
        "coi must not change Incus profiles, networks or pools"
    )
