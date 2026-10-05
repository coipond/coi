"""
`coi container delete` must reclaim ALL host-side firewall artefacts (#696 item 5).

Before the fix, `coi container delete` removed only the IPv4 `coi-<ip>` rule
bundle; it left the monitoring LOG rules (`NFT_*[ip]` in `ip filter FORWARD`)
and the NAME-keyed `coi6-<name>` IPv6 block behind, so they leaked until an
exact-IP DHCP reuse or a manual `coi clean --orphans`. The command now routes
through the shared `cleanupContainerFirewall`, the same one kill/shutdown use.

This drives the real CLI against real nft and asserts a specific container's
artefacts are all gone after delete. It snapshots that container's IP/name and
polls (nft cleanup is async and CI runners are loaded); it never assumes an
empty global chain.
"""

import json
import os
import subprocess
import tempfile
import time

import pytest


def _skip_unless_ready():
    if subprocess.run(["which", "incus"], capture_output=True).returncode != 0:
        return "incus not found"
    if subprocess.run(["which", "nft"], capture_output=True).returncode != 0:
        return "nft not found"
    if subprocess.run(["sudo", "-n", "nft", "list", "tables"], capture_output=True).returncode != 0:
        return "nft sudo not available"
    return None


def _get_container_ip(coi_binary, name):
    r = subprocess.run(
        [coi_binary, "container", "exec", name, "--capture", "--", "hostname", "-I"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if r.returncode != 0:
        return None
    try:
        stdout = json.loads(r.stdout).get("stdout", "").strip()
    except json.JSONDecodeError:
        stdout = r.stdout.strip()
    for ip in stdout.split():
        if ip.startswith("10."):
            return ip
    parts = stdout.split()
    return parts[0] if parts else None


def _count_rules_for_ip(ip):
    r = subprocess.run(
        ["sudo", "-n", "nft", "-a", "list", "chain", "ip", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if r.returncode != 0:
        return 0
    marker = f'comment "coi-{ip}"'
    return sum(1 for line in r.stdout.splitlines() if marker in line)


def _count_monitor_rules_for_ip(ip):
    r = subprocess.run(
        ["sudo", "-n", "nft", "-a", "list", "chain", "ip", "filter", "FORWARD"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if r.returncode != 0:
        return 0
    tokens = (f"NFT_COI[{ip}]", f"NFT_DNS[{ip}]", f"NFT_SUSPICIOUS[{ip}]")
    return sum(1 for line in r.stdout.splitlines() if any(t in line for t in tokens))


def _ip6_chain():
    r = subprocess.run(
        ["sudo", "-n", "nft", "list", "chain", "ip6", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.stdout if r.returncode == 0 else ""


def _wait_for_rules_for_ip(coi_binary, name, timeout=20):
    deadline = time.time() + timeout
    ip, count = "", 0
    while time.time() < deadline:
        if not ip:
            ip = _get_container_ip(coi_binary, name) or ""
        if ip:
            count = _count_rules_for_ip(ip)
            if count > 0:
                return ip, count
        time.sleep(0.5)
    return ip, count


def _poll_until(fn, timeout=15):
    """Poll fn() until it returns True (or timeout); return its final value."""
    deadline = time.time() + timeout
    val = fn()
    while not val and time.time() < deadline:
        time.sleep(1)
        val = fn()
    return val


def test_container_delete_removes_all_firewall_artifacts(
    coi_binary, workspace_dir, cleanup_containers
):
    reason = _skip_unless_ready()
    if reason:
        pytest.skip(reason)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write('[network]\nmode = "restricted"\n')
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

        ip, count = _wait_for_rules_for_ip(coi_binary, name)
        if not ip:
            pytest.skip("container never got a DHCP IP; cannot assert rule cleanup")
        assert count > 0, f"precondition: expected coi-{ip} rules while running"

        comment = f"coi6-{name}"
        assert comment in _ip6_chain(), f"precondition: {comment} present while running"

        # Delete the container — must reclaim the IPv4 bundle and IPv6 block.
        # (The monitoring LOG-rule path is covered by the dedicated,
        # monitoring-gated test below.)
        dele = subprocess.run(
            [coi_binary, "container", "delete", name, "--force"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert dele.returncode == 0, f"container delete failed: {dele.stderr}"

        assert _poll_until(lambda: _count_rules_for_ip(ip) == 0), (
            f"coi-{ip} IPv4 rules still present after delete"
        )
        assert _poll_until(lambda: comment not in _ip6_chain()), (
            f"{comment} IPv6 block still present after delete:\n{_ip6_chain()}"
        )
    finally:
        os.unlink(config_file)


def _monitoring_available():
    """nft monitoring needs nft-with-sudo AND journal access (the daemon reads
    the kernel log). Mirrors tests/integration/test_nft_monitoring.py's gate."""
    if (
        subprocess.run(["sudo", "-n", "nft", "list", "ruleset"], capture_output=True).returncode
        != 0
    ):
        return "nft sudo not available"
    if subprocess.run(["journalctl", "-n", "1", "-k"], capture_output=True).returncode != 0:
        return "journal access not available"
    return None


def _poll_for_monitor_rules(ip, timeout=40):
    """Poll until >=1 NFT_*[ip] LOG rule appears (the daemon installs them
    asynchronously after the session starts); return the final count."""
    deadline = time.time() + timeout
    count = _count_monitor_rules_for_ip(ip)
    while count == 0 and time.time() < deadline:
        time.sleep(1)
        count = _count_monitor_rules_for_ip(ip)
    return count


def test_container_delete_removes_monitoring_log_rules(
    coi_binary, workspace_dir, cleanup_containers
):
    """`coi container delete` must also remove the NFT_*[ip] monitoring LOG rules
    in `ip filter FORWARD` (#696 item 5). This is the artefact the old inline
    RemoveRules() left behind. Enables nft monitoring so the rules actually
    exist, then asserts they are gone after delete. Skips (never silently
    passes) when monitoring can't run in this environment."""
    reason = _skip_unless_ready() or _monitoring_available()
    if reason:
        pytest.skip(reason)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(
            "[monitoring]\nenabled = true\n\n"
            "[monitoring.nft]\nenabled = true\n\n"
            '[network]\nmode = "restricted"\n'
        )
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

        ip, _count = _wait_for_rules_for_ip(coi_binary, name)
        assert ip, f"{name} never got a DHCP IP"

        # The monitoring daemon installs the LOG rules asynchronously; require
        # them as a precondition so this test genuinely exercises their removal.
        assert _poll_for_monitor_rules(ip) > 0, (
            f"nft monitoring LOG rules for {ip} were never installed"
        )

        dele = subprocess.run(
            [coi_binary, "container", "delete", name, "--force"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert dele.returncode == 0, f"container delete failed: {dele.stderr}"

        assert _poll_until(lambda: _count_monitor_rules_for_ip(ip) == 0), (
            f"NFT_*[{ip}] monitoring LOG rules still present after delete (#696 item 5)"
        )
    finally:
        os.unlink(config_file)
