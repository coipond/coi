"""
`coi unfreeze` without a name, on a container that is not frozen, and
`coi list --status frozen`.

The existing unfreeze tests always pass a name. With no name, coi unfreezes
every frozen `coi-*` container and prints `Unfroze N container(s)`, or
`No frozen Coi containers found` when there is none. A named container that is
not frozen is an error.

Setup: two containers from coi-default; the second is paused with `incus pause`.
"""

import json
import subprocess

from support.helpers import calculate_container_name


def _coi(coi_binary, *args):
    return subprocess.run(
        [coi_binary, *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _incus_status(name):
    result = subprocess.run(
        ["incus", "list", name, "--format=csv", "-c", "s"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip().upper()


def _frozen_coi_containers():
    """Frozen `coi-*` containers, read the way `coi unfreeze` reads them."""
    result = subprocess.run(
        ["incus", "list", "--format", "csv", "-c", "ns"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"incus list failed: {result.stderr}"
    frozen = []
    for line in result.stdout.splitlines():
        name, _, status = line.partition(",")
        if name.startswith("coi-") and status.strip().lower() == "frozen":
            frozen.append(name)
    return frozen


def test_unfreeze_all_and_not_frozen(coi_binary, cleanup_containers, workspace_dir):
    """
    Unfreeze-all, the not-frozen error and the frozen list filter.

    Flow:
    1. Launch two containers; pause the second
    2. `coi list --status frozen` lists only the paused container
    3. `coi unfreeze <running>` fails: not frozen
    4. `coi unfreeze` unfreezes the paused container: `Unfroze N container(s)`
    5. `coi unfreeze` again: `No frozen Coi containers found`
    """
    running_name = calculate_container_name(workspace_dir, 1)
    frozen_name = calculate_container_name(workspace_dir, 2)

    # === Phase 1: One running, one frozen container ===

    for name in (running_name, frozen_name):
        result = _coi(coi_binary, "container", "launch", "coi-default", name)
        assert result.returncode == 0, f"launch of {name} failed: {result.stderr}"

    result = subprocess.run(
        ["incus", "pause", frozen_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"incus pause failed: {result.stderr}"
    assert _incus_status(frozen_name) == "FROZEN"

    # === Phase 2: list --status frozen ===

    result = _coi(coi_binary, "list", "--status", "frozen", "--format", "json")
    assert result.returncode == 0, f"list --status frozen failed: {result.stderr}"
    containers = json.loads(result.stdout)["active_containers"]
    names = {c["name"] for c in containers}
    assert frozen_name in names, f"the paused container is missing: {names}"
    assert running_name not in names, f"the running container must be filtered out: {names}"
    for c in containers:
        assert c["status"].lower() == "frozen", f"{c['name']} is {c['status']}, not frozen"

    # === Phase 3: Named unfreeze of a running container fails ===

    result = _coi(coi_binary, "unfreeze", running_name)
    output = result.stdout + result.stderr
    assert result.returncode != 0, f"unfreezing a running container must fail:\n{output}"
    assert f"container {running_name} is not frozen (status: running)" in output.lower(), (
        f"expected a not-frozen error:\n{output}"
    )

    # === Phase 4: Unfreeze all ===

    frozen = _frozen_coi_containers()
    assert frozen_name in frozen, f"the paused container is not listed as frozen: {frozen}"

    result = _coi(coi_binary, "unfreeze")
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"coi unfreeze failed:\n{output}"
    assert f"Unfroze container: {frozen_name}" in output, output
    assert f"Unfroze {len(frozen)} container(s)" in output, (
        f"expected the count of frozen coi-* containers ({frozen}):\n{output}"
    )
    assert _incus_status(frozen_name) == "RUNNING"
    assert _incus_status(running_name) == "RUNNING"

    # === Phase 5: Nothing left to unfreeze ===

    result = _coi(coi_binary, "unfreeze")
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"coi unfreeze failed:\n{output}"
    assert "No frozen Coi containers found" in output, output
