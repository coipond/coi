"""
Project (.coi/config.toml) config must not be able to weaken network isolation.

A repo-supplied or agent-planted project config that sets
block_metadata_endpoint=false / block_private_networks=false / mode=open is a
silent downgrade of the secure defaults. Coi refuses such downgrades from
project scope (with a warning); only the user's ~/.coi/config.toml or an
explicit COI_CONFIG may relax them.
"""

import json
import re
import subprocess
from pathlib import Path

import pytest

from support.helpers import wait_for_firewall_rules, write_trusted_coi_config


def test_project_config_network_downgrade_refused(coi_binary, cleanup_containers, workspace_dir):
    """A project config disabling the metadata/private-network blocks is ignored with a warning."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        "[network]\n"
        'mode = "restricted"\n'
        "block_metadata_endpoint = false\n"
        "block_private_networks = false\n"
    )

    result = subprocess.run(
        [coi_binary, "run", "--", "true"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
    )

    combined = result.stdout + result.stderr
    assert "ignoring security-downgrading" in combined.lower(), (
        f"Expected a warning that the project network downgrade was ignored.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # Both downgrade flags should be named in the warnings.
    assert "block_metadata_endpoint" in combined, f"missing metadata warning:\n{combined}"
    assert "block_private_networks" in combined, f"missing private-networks warning:\n{combined}"


# ── Runtime proof: a stripped downgrade leaves the protection actually in place ──
#
# The tests above assert the downgrade *warning*. These additionally prove the
# guard HOLDS AT RUNTIME by probing the local gateway — a live RFC1918 host that
# is reachable when the local-network block is off and blocked when it is on.
# (A dead RFC1918 IP can't distinguish "firewall blocked" from "nothing there";
# the gateway responds, so it can.)


def _start_background_shell(coi_binary, workspace_dir, env=None):
    """Start a `--background` shell for the workspace; return (container_name, stderr)."""
    r = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background", "--debug"],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )
    assert r.returncode == 0, f"background shell should start. stderr: {r.stderr}"
    name = None
    for line in r.stderr.split("\n"):
        if "Container name:" in line:
            name = line.split("Container name:")[-1].strip()
            break
    assert name, f"could not find container name in output. stderr: {r.stderr}"
    return name, r.stderr


def _discover_gateway(coi_binary, container_name):
    """Return the container's default-gateway IP (an RFC1918 host that responds)."""
    r = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "ip", "route", "show", "default"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # `coi container exec` surfaces the guest command's output on stderr.
    out = r.stderr.strip()
    if "default via" in out:
        parts = out.split()
        try:
            return parts[parts.index("via") + 1]
        except (ValueError, IndexError):
            return None
    return None


def _gateway_reachable(coi_binary, container_name, gateway_ip):
    r = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "curl",
            "-s",
            "--connect-timeout",
            "2",
            f"http://{gateway_ip}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.returncode == 0


@pytest.mark.parametrize(
    "downgrade_line, warning_token",
    [
        ("block_private_networks = false", "block_private_networks"),
        ("allow_local_network_access = true", "allow_local_network_access"),
    ],
)
def test_untrusted_network_downgrade_gateway_still_blocked(
    coi_binary, cleanup_containers, workspace_dir, downgrade_line, warning_token
):
    """An untrusted project downgrade is ignored at RUNTIME, not just warned about.

    Base mode is restricted; the downgrade would open the local network. The
    sanitizer strips it, so the RFC1918 gateway (a live host that responds when
    reachable) stays blocked — proving the guard actually held, not merely that a
    warning printed.
    """
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(f'[network]\nmode = "restricted"\n{downgrade_line}\n')

    container_name, setup_stderr = _start_background_shell(coi_binary, workspace_dir)
    wait_for_firewall_rules(container_name)

    gateway_ip = _discover_gateway(coi_binary, container_name)
    assert gateway_ip is not None, f"should discover the gateway IP for {container_name}"
    assert not _gateway_reachable(coi_binary, container_name, gateway_ip), (
        f"{warning_token}: the RFC1918 gateway {gateway_ip} was reachable — the untrusted "
        "downgrade was honored instead of stripped"
    )
    combined = setup_stderr.lower()
    assert "ignoring security-downgrading" in combined and warning_token in combined, (
        f"{warning_token}: expected the downgrade warning during setup.\n{setup_stderr}"
    )


def test_untrusted_mode_open_downgrade_ignored(coi_binary, cleanup_containers, workspace_dir):
    """`mode = "open"` from an untrusted project config is stripped, so the container
    runs restricted (the default) and the RFC1918 gateway stays blocked — if it were
    honored, open mode would make the gateway reachable. The downgrade is announced.
    """
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text('[network]\nmode = "open"\n')

    container_name, setup_stderr = _start_background_shell(coi_binary, workspace_dir)
    wait_for_firewall_rules(container_name)

    gateway_ip = _discover_gateway(coi_binary, container_name)
    assert gateway_ip is not None, f"should discover the gateway IP for {container_name}"
    assert not _gateway_reachable(coi_binary, container_name, gateway_ip), (
        f"mode=open honored — gateway {gateway_ip} reachable; the downgrade to open was not stripped"
    )
    combined = setup_stderr.lower()
    assert "ignoring security-downgrading" in combined and "network.mode=open" in combined, (
        f"expected the mode=open downgrade warning during setup.\n{setup_stderr}"
    )


# ── block_metadata_endpoint: dropped when false, kept when true ──
#
# CI has no cloud metadata service, so curling 169.254.169.254 fails whether or
# not it is blocked and proves nothing. Instead assert on the container's own
# `ip daddr 169.254.0.0/16 reject` rule in the coi forward chain, and use a
# trusted COI_CONFIG that turns the block OFF as the baseline, so a rule can
# only be present because the untrusted project's `true` was honored.

METADATA_REJECT = "ip daddr 169.254.0.0/16 reject"


def _container_ip(container_name):
    r = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if r.returncode != 0 or not r.stdout.strip():
        return None
    info = json.loads(r.stdout)
    if not info:
        return None
    for addr in info[0].get("state", {}).get("network", {}).get("eth0", {}).get("addresses", []):
        if addr.get("family") == "inet":
            return addr["address"]
    return None


def _metadata_reject_rules(container_name):
    """The container's metadata-block reject rules in the ip coi forward chain."""
    ip = _container_ip(container_name)
    assert ip, f"could not resolve the IPv4 address of {container_name}"
    r = subprocess.run(
        ["sudo", "-n", "nft", "list", "chain", "ip", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert r.returncode == 0, f"nft list failed: {r.stderr}"
    src = re.compile(r"ip saddr " + re.escape(ip) + r"(?![\d.])")
    return [ln.strip() for ln in r.stdout.splitlines() if src.search(ln) and METADATA_REJECT in ln]


@pytest.mark.parametrize(
    "trusted, project, want_rule, want_warning",
    [
        # The untrusted downgrade is dropped: the secure default still blocks.
        (None, "block_metadata_endpoint = false", True, True),
        # Control: a TRUSTED config can turn the block off.
        ("block_metadata_endpoint = false", None, False, False),
        # The untrusted strengthening is kept: it re-enables the block the
        # trusted config turned off, silently.
        ("block_metadata_endpoint = false", "block_metadata_endpoint = true", True, False),
    ],
    ids=["project-false-dropped", "trusted-false-control", "project-true-kept"],
)
def test_untrusted_block_metadata_endpoint_sanitized(
    coi_binary, cleanup_containers, workspace_dir, trusted, project, want_rule, want_warning
):
    """An untrusted `block_metadata_endpoint = false` is dropped and `= true` is
    kept, proven by the container's actual nft metadata reject rule (#7)."""
    env = None
    if trusted:
        env = write_trusted_coi_config(f'[network]\nmode = "restricted"\n{trusted}\n')
    if project:
        config_dir = Path(workspace_dir) / ".coi"
        config_dir.mkdir(exist_ok=True)
        (config_dir / "config.toml").write_text(f'[network]\nmode = "restricted"\n{project}\n')

    container_name, setup_stderr = _start_background_shell(coi_binary, workspace_dir, env)
    assert wait_for_firewall_rules(container_name), f"no firewall rules for {container_name}"

    rules = _metadata_reject_rules(container_name)
    if want_rule:
        assert rules, (
            f"expected a 169.254.0.0/16 reject rule for {container_name} "
            f"(trusted={trusted!r}, project={project!r})\n{setup_stderr}"
        )
    else:
        assert not rules, f"trusted block_metadata_endpoint=false should leave no rule, got {rules}"

    warned = "network.block_metadata_endpoint=false" in setup_stderr
    assert warned == want_warning, (
        f"downgrade warning expected={want_warning}, got={warned}\n{setup_stderr}"
    )
