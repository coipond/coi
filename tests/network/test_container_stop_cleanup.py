"""
`coi container stop` must reclaim the container's host-side firewall artefacts.

A container's IPv4 rule bundle is keyed by its IP (`coi-<ip>`), and a stopped
container reports no IP. A `coi shell --background` session never runs the
session teardown, so stopping it with `coi container stop` left the bundle (and
the `coi6-<name>` IPv6 block) behind, and a later `coi container delete` could no
longer find it: one leaked bundle per background run until `coi clean --orphans`.
Stop now reads the IP first and removes everything after a successful stop.

Removing them on stop is safe because every start re-applies the rules for the
IP the container gets then; the second half of this test proves that by
restarting the persistent container.
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


def _ip6_chain():
    r = subprocess.run(
        ["sudo", "-n", "nft", "list", "chain", "ip6", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.stdout if r.returncode == 0 else ""


def _container_status(name):
    r = subprocess.run(
        ["incus", "list", name, "--format=csv", "-c", "ns"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        parts = line.split(",")
        if len(parts) >= 2 and parts[0] == name:
            return parts[1].strip()
    return None


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
    deadline = time.time() + timeout
    val = fn()
    while not val and time.time() < deadline:
        time.sleep(1)
        val = fn()
    return val


def _start_background(coi_binary, workspace_dir, env):
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
            return line.split("Container: ")[1].strip()
    raise AssertionError(f"no container name: {result.stdout + result.stderr}")


def test_container_stop_removes_firewall_artifacts_and_start_restores_them(
    coi_binary, workspace_dir, cleanup_containers
):
    reason = _skip_unless_ready()
    if reason:
        pytest.skip(reason)

    # Persistent so the stopped container stays (and a restart reuses it);
    # restricted so the coi-<ip> bundle and the coi6-<name> block are installed.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write('[container]\npersistent = true\n[network]\nmode = "restricted"\n')
        config_file = f.name

    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        name = _start_background(coi_binary, workspace_dir, env)

        ip, count = _wait_for_rules_for_ip(coi_binary, name)
        if not ip:
            pytest.skip("container never got a DHCP IP; cannot assert rule cleanup")
        assert count > 0, f"precondition: expected coi-{ip} rules while running"
        comment = f"coi6-{name}"
        assert comment in _ip6_chain(), f"precondition: {comment} present while running"

        stop = subprocess.run(
            [coi_binary, "container", "stop", name, "--force"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert stop.returncode == 0, f"container stop failed: {stop.stderr}"
        assert _container_status(name) == "STOPPED", "stop should keep the persistent container"

        assert _poll_until(lambda: _count_rules_for_ip(ip) == 0), (
            f"coi-{ip} IPv4 rules still present after stop"
        )
        assert _poll_until(lambda: comment not in _ip6_chain()), (
            f"{comment} IPv6 block still present after stop:\n{_ip6_chain()}"
        )

        # Restart: the same persistent container comes back with its rules re-applied.
        again = _start_background(coi_binary, workspace_dir, env)
        assert again == name, f"expected the persistent container {name} to be reused, got {again}"
        new_ip, new_count = _wait_for_rules_for_ip(coi_binary, name)
        assert new_ip and new_count > 0, f"rules should be re-applied on restart (ip={new_ip!r})"
        assert _poll_until(lambda: comment in _ip6_chain()), (
            f"{comment} IPv6 block should be re-applied on restart"
        )
    finally:
        os.unlink(config_file)
