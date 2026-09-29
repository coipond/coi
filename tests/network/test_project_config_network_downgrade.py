"""
Project (.coi/config.toml) config must not be able to weaken network isolation.

A repo-supplied or agent-planted project config that sets
block_metadata_endpoint=false / block_private_networks=false / mode=open is a
silent downgrade of the secure defaults. Coi refuses such downgrades from
project scope (with a warning); only the user's ~/.coi/config.toml or an
explicit COI_CONFIG may relax them.
"""

import subprocess
from pathlib import Path

import pytest

from support.helpers import wait_for_firewall_rules


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


def _start_background_shell(coi_binary, workspace_dir):
    """Start a `--background` shell for the workspace; return (container_name, stderr)."""
    r = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background", "--debug"],
        capture_output=True,
        text=True,
        timeout=90,
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
