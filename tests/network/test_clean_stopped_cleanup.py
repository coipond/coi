"""
Default `coi clean` must reclaim a stopped container's firewall artefacts (#696 item 4).

The default reap path (`coi clean`, no `--orphans`) deletes stopped coi
containers. Before the fix it deleted them with zero nft cleanup, so the
NAME-keyed `coi6-<name>` IPv6 block (and, when the IP is still known, the
`coi-<ip>` bundle) leaked until an exact-IP DHCP reuse or a manual
`coi clean --orphans`. The reap loop now calls the shared
`cleanupContainerFirewall` on each container before deleting it.

This test proves the reliable, environment-independent part: the name-keyed
`coi6-<name>` block is removed by a default `coi clean`. (A *stopped*
container no longer reports a DHCP IP, so its IP-keyed IPv4/LOG rules are
reclaimed by the orphan sweep rather than this path — a documented limitation;
we don't assert on them here.) Uses a persistent container so `incus stop`
leaves it Stopped-not-deleted, giving `coi clean` something to reap.
"""

import os
import subprocess
import tempfile
import time

import pytest

from support.helpers import incus_status


def _skip_unless_ready():
    if subprocess.run(["which", "incus"], capture_output=True).returncode != 0:
        return "incus not found"
    if subprocess.run(["which", "nft"], capture_output=True).returncode != 0:
        return "nft not found"
    if subprocess.run(["sudo", "-n", "nft", "list", "tables"], capture_output=True).returncode != 0:
        return "nft sudo not available"
    return None


def _ip6_chain():
    r = subprocess.run(
        ["sudo", "-n", "nft", "list", "chain", "ip6", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.stdout if r.returncode == 0 else ""


def _poll_until(fn, timeout=20):
    deadline = time.time() + timeout
    val = fn()
    while not val and time.time() < deadline:
        time.sleep(1)
        val = fn()
    return val


def test_default_clean_reclaims_stopped_container_ipv6_block(
    coi_binary, workspace_dir, cleanup_containers
):
    reason = _skip_unless_ready()
    if reason:
        pytest.skip(reason)

    # Persistent so `incus stop` leaves it Stopped (an ephemeral container is
    # auto-deleted on stop); restricted so the coi6-<name> block is installed.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write('[container]\npersistent = true\n[network]\nmode = "restricted"\n')
        config_file = f.name

    name = None
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
                name = line.split("Container: ")[1].strip()
                break
        assert name, f"no container name: {result.stdout + result.stderr}"

        comment = f"coi6-{name}"
        assert comment in _ip6_chain(), f"precondition: {comment} present while running"

        # Stop WITHOUT coi teardown, leaving the host-side block behind.
        subprocess.run(
            ["incus", "stop", name, "--force"], capture_output=True, timeout=60, check=False
        )

        status = incus_status(name)
        if status != "STOPPED":
            pytest.skip(
                f"container not in STOPPED state after stop (got {status!r}); cannot exercise reap path"
            )
        assert comment in _ip6_chain(), (
            f"precondition: {comment} should still be present (orphaned) after stop"
        )

        # Default reap path (NOT --orphans) must now clean the block.
        clean = subprocess.run(
            [coi_binary, "clean", "--force"],
            capture_output=True,
            text=True,
            timeout=90,
            env=env,
        )
        assert clean.returncode == 0, f"coi clean failed: {clean.stderr}"

        assert _poll_until(lambda: comment not in _ip6_chain()), (
            f"default coi clean should remove {comment} when reaping the stopped container:\n{_ip6_chain()}"
        )
    finally:
        os.unlink(config_file)
