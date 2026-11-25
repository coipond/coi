"""
`coi clean --orphans` must remove orphaned IPv6 drop chains.

Restricted/allowlist mode installs a host-side IPv6 drop chain `coi6-<container>`
in the `netdev coi` table, hooked on the container's veth. It is removed on normal
teardown, but a container that is force-deleted (no coi teardown) can leave the
chain behind (on kernels that do not delete it together with the veth). A
container killed before its mode's rules leaves its `coi-boot-<container>` chain,
and older coi versions left a `coi6-<container>` rule in `ip6 coi forward`.
Orphan cleanup, which already sweeps stale IPv4 `ip coi` rules, must remove all
of them.
"""

import os
import subprocess
import tempfile

import pytest

from support.helpers import dummy_netdev_chains, netdev_coi


def _skip_unless_ready():
    if subprocess.run(["which", "incus"], capture_output=True).returncode != 0:
        return "incus not found"
    if subprocess.run(["which", "nft"], capture_output=True).returncode != 0:
        return "nft not found"
    if subprocess.run(["sudo", "-n", "nft", "list", "tables"], capture_output=True).returncode != 0:
        return "nft sudo not available"
    return None


def _legacy_ip6_chain():
    r = subprocess.run(
        ["sudo", "-n", "nft", "list", "chain", "ip6", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.stdout if r.returncode == 0 else ""


def test_clean_orphans_removes_stale_ip6_rule(coi_binary, workspace_dir, cleanup_containers):
    reason = _skip_unless_ready()
    if reason:
        pytest.skip(reason)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write('[network]\nmode = "restricted"\n')
        config_file = f.name

    container_name = None
    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        result = subprocess.run(
            [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        assert result.returncode == 0, f"Failed to start container: {result.stderr}"
        for line in (result.stdout + result.stderr).split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break
        assert container_name, f"no container name: {result.stdout + result.stderr}"

        comment = f"coi6-{container_name}"
        # In restricted mode the host-side ip6 drop is fatal-on-failure, so a
        # started container guarantees the rule exists.
        assert comment in netdev_coi(), (
            f"expected {comment} in netdev coi after start:\n{netdev_coi()}"
        )

        # Force-delete the container WITHOUT coi teardown — this orphans the rule.
        subprocess.run(
            ["incus", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
            check=False,
        )
        # A kernel that deletes the chain with the veth leaves nothing: plant
        # it as a kernel that keeps it would. Plant the boot chain and the
        # legacy ip6 rule of the same dead container on every kernel.
        boot = f"coi-boot-{container_name}"
        planted = [boot] if comment in netdev_coi() else [comment, boot]
        with dummy_netdev_chains(*planted, legacy_ip6=[container_name]):
            assert f"chain {comment} {{" in netdev_coi() and f"chain {boot} {{" in netdev_coi()
            assert f'comment "{comment}"' in _legacy_ip6_chain()

            # Orphan cleanup must remove them all.
            clean = subprocess.run(
                [coi_binary, "clean", "--orphans", "--force"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert clean.returncode == 0, f"coi clean failed: {clean.stderr}"
            assert "Orphaned drop chains" in clean.stdout, clean.stdout
            for chain in (comment, boot):
                assert f"chain {chain} {{" not in netdev_coi(), (
                    f"orphaned chain {chain} should be removed by clean --orphans:\n{netdev_coi()}"
                )
            assert f'comment "{comment}"' not in _legacy_ip6_chain(), (
                f"legacy ip6 rule {comment} should be removed:\n{_legacy_ip6_chain()}"
            )
    finally:
        os.unlink(config_file)
