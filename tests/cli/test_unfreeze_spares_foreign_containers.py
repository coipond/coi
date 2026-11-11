"""
`coi unfreeze` without a name unfreezes only coi containers.

Setup: a coi container and the foreign running containers (one of them named
`web-coi-...`) are all paused with `incus pause`. coi must unfreeze its own
container and leave the foreign ones frozen.
"""

import subprocess

from support.helpers import calculate_container_name, incus_status


def test_unfreeze_spares_foreign_containers(
    coi_binary, cleanup_containers, workspace_dir, foreign_containers
):
    container_name = calculate_container_name(workspace_dir, 1)
    paused_foreign = [foreign_containers["running"], foreign_containers["lookalike"]]

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    for name in [container_name, *paused_foreign]:
        result = subprocess.run(
            ["incus", "pause", name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"incus pause {name} failed: {result.stderr}"
        assert incus_status(name) == "FROZEN"

    result = subprocess.run(
        [coi_binary, "unfreeze"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"unfreeze failed: {result.stderr}"
    assert "Unfroze 1 container(s)" in result.stderr, result.stderr

    assert incus_status(container_name) == "RUNNING"
    for name in paused_foreign:
        assert incus_status(name) == "FROZEN", f"coi unfreeze must not unfreeze {name}"
