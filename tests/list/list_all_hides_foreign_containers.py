"""
Test for coi list --all - shows only coi containers.

Tests that:
1. Launch a coi container next to foreign containers (running, stopped, and
   one whose name holds "coi-" but does not start with it)
2. Verify coi list --all --format json lists the coi container only
3. Verify the text output names no foreign container
"""

import json
import subprocess

from support.helpers import calculate_container_name


def test_list_all_hides_foreign_containers(
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
        [coi_binary, "list", "--all", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"List should succeed. stderr: {result.stderr}"

    names = [c["name"] for c in json.loads(result.stdout)["active_containers"]]
    assert container_name in names, f"coi container should be listed: {names}"
    for name in foreign:
        assert name not in names, f"Foreign container {name} must not be listed: {names}"

    result = subprocess.run(
        [coi_binary, "list", "--all"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"List should succeed. stderr: {result.stderr}"
    for name in foreign:
        assert name not in result.stdout, f"Foreign container {name} must not be listed"
