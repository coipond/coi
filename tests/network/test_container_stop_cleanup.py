"""
`coi container stop` must reclaim the container's host-side firewall artefacts.

A container's IPv4 rule bundle is keyed by its IP (`coi-<ip>`), and a stopped
container reports no IP. A `coi shell --background` session never runs the
session teardown, so stopping it with `coi container stop` left the bundle (and
the `coi6-<name>` IPv6 block) behind, and a later `coi container delete` could no
longer find it: one leaked bundle per background run until `coi clean --orphans`.
Stop now reads the IP first and removes everything after a successful stop.

Removing them on stop is safe because every start re-applies the rules for the
IP the container gets then: through `coi shell` and, since the same fix, through
a bare `coi container start` too, which used to bring the container back with no
firewall at all.

The IPv6 block matches the container's veth by name, and every start gets a new
veth. A stop that skips cleanup (`incus stop`, a poweroff inside the container)
leaves a coi6-<name> rule naming a dead veth; setup used to see that comment,
skip, and leave the new veth with no IPv6 block. The tests below check the rule
names the container's current veth, not just that the comment exists.
"""

import json
import os
import re
import subprocess
import tempfile
import time

import pytest

from support.helpers import calculate_container_name


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
    # A failed listing must not read as "no rules", or a cleanup check passes
    # without having looked.
    assert r.returncode == 0, f"nft list chain ip coi forward failed: {r.stderr}"
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


def _ip6_block_veths(name):
    """The veths named by the container's coi6-<name> rules, one per rule."""
    comment = f'comment "coi6-{name}"'
    veths = []
    for line in _ip6_chain().splitlines():
        if comment in line:
            m = re.search(r'iifname "([^"]+)"', line)
            veths.append(m.group(1) if m else line.strip())
    return veths


def _current_veth(name):
    r = subprocess.run(
        ["incus", "config", "get", name, "volatile.eth0.host_name"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return r.stdout.strip() if r.returncode == 0 else ""


def _assert_ip6_block_on_current_veth(name, timeout=20):
    """Exactly one coi6-<name> rule, and it drops the veth the container has now."""
    deadline = time.time() + timeout
    veth, rules = "", []
    while time.time() < deadline:
        veth, rules = _current_veth(name), _ip6_block_veths(name)
        if veth and rules == [veth]:
            return
        time.sleep(1)
    raise AssertionError(
        f"coi6-{name} should drop exactly the current veth {veth!r}, got rules for {rules}"
    )


def _coi_stop(coi_binary, name):
    stop = subprocess.run(
        [coi_binary, "container", "stop", name, "--force"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert stop.returncode == 0, f"container stop failed: {stop.stderr}"
    assert _container_status(name) == "STOPPED", "stop should keep the persistent container"


def _write_config(mode="restricted"):
    # Persistent so the stopped container stays (and a restart reuses it);
    # restricted so the coi-<ip> bundle and the coi6-<name> block are installed.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(f'[container]\npersistent = true\n[network]\nmode = "{mode}"\n')
        return f.name


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

    config_file = _write_config()
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

        _coi_stop(coi_binary, name)

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
        _assert_ip6_block_on_current_veth(name)
    finally:
        os.unlink(config_file)


def test_container_start_after_stop_reapplies_firewall(
    coi_binary, workspace_dir, cleanup_containers
):
    """A bare `coi container start` must not bring a stopped container back unfiltered."""
    reason = _skip_unless_ready()
    if reason:
        pytest.skip(reason)

    config_file = _write_config()
    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        name = _start_background(coi_binary, workspace_dir, env)
        ip, count = _wait_for_rules_for_ip(coi_binary, name)
        if not ip:
            pytest.skip("container never got a DHCP IP; cannot assert rule cleanup")
        assert count > 0, f"precondition: expected coi-{ip} rules while running"

        _coi_stop(coi_binary, name)
        assert _count_rules_for_ip(ip) == 0, f"coi-{ip} rules should be gone after stop"
        assert _ip6_block_veths(name) == [], "coi6 block should be gone after stop"

        start = subprocess.run(
            [coi_binary, "container", "start", name],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        assert start.returncode == 0, f"container start failed: {start.stderr}"
        assert _container_status(name) == "RUNNING", "start should leave the container running"

        new_ip, new_count = _wait_for_rules_for_ip(coi_binary, name)
        assert new_ip and new_count > 0, (
            f"coi container start should re-apply the coi-<ip> rules (ip={new_ip!r})"
        )
        _assert_ip6_block_on_current_veth(name)
        boot_block = f'comment "coi-boot-{name}"'
        assert _poll_until(
            lambda: (
                boot_block
                not in subprocess.run(
                    ["sudo", "-n", "nft", "list", "chain", "ip", "coi", "forward"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout
            )
        ), "the boot block should be lifted once the rules are in place"
    finally:
        os.unlink(config_file)


def test_ip6_block_follows_new_veth_after_unclean_stop(
    coi_binary, workspace_dir, cleanup_containers
):
    """A coi6 rule left on a dead veth must be replaced, not taken as already installed."""
    reason = _skip_unless_ready()
    if reason:
        pytest.skip(reason)

    config_file = _write_config()
    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        name = _start_background(coi_binary, workspace_dir, env)
        _assert_ip6_block_on_current_veth(name)
        old_veth = _current_veth(name)

        # Stop behind coi's back, as `incus stop` or a poweroff inside the
        # container does: no coi code runs, so the coi6 rule stays on the old veth.
        r = subprocess.run(
            ["incus", "stop", name, "--force"], capture_output=True, text=True, timeout=60
        )
        assert r.returncode == 0, f"incus stop failed: {r.stderr}"
        assert _ip6_block_veths(name) == [old_veth], (
            "precondition: the coi6 rule should be left behind on the old veth"
        )

        again = _start_background(coi_binary, workspace_dir, env)
        assert again == name, f"expected the persistent container {name} to be reused, got {again}"
        new_veth = _current_veth(name)
        assert new_veth and new_veth != old_veth, (
            f"precondition: Incus should give the restarted container a new veth ({old_veth!r})"
        )
        _assert_ip6_block_on_current_veth(name)
    finally:
        os.unlink(config_file)


def test_container_launch_applies_firewall(coi_binary, workspace_dir, cleanup_containers):
    """`coi container launch` must not start a container with no firewall."""
    reason = _skip_unless_ready()
    if reason:
        pytest.skip(reason)

    config_file = _write_config()
    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        name = calculate_container_name(workspace_dir, 1)
        launch = subprocess.run(
            [coi_binary, "container", "launch", "coi-default", name],
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
        assert launch.returncode == 0, f"container launch failed: {launch.stderr}"
        assert _container_status(name) == "RUNNING", "launch should leave the container running"

        ip, count = _wait_for_rules_for_ip(coi_binary, name)
        assert ip and count > 0, f"coi container launch should apply the coi-<ip> rules (ip={ip!r})"
        _assert_ip6_block_on_current_veth(name)
        boot_block = f'comment "coi-boot-{name}"'
        assert _poll_until(
            lambda: (
                boot_block
                not in subprocess.run(
                    ["sudo", "-n", "nft", "list", "chain", "ip", "coi", "forward"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout
            )
        ), "the boot block should be lifted once the rules are in place"
    finally:
        os.unlink(config_file)


def test_container_start_after_stop_restores_open_mode_accept_rule(
    coi_binary, workspace_dir, cleanup_containers
):
    """Stop removes open mode's coi-<ip> accept rule; a bare start must put it back."""
    reason = _skip_unless_ready()
    if reason:
        pytest.skip(reason)

    config_file = _write_config(mode="open")
    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        name = _start_background(coi_binary, workspace_dir, env)
        ip, count = _wait_for_rules_for_ip(coi_binary, name)
        if not ip:
            pytest.skip("container never got a DHCP IP; cannot assert rule cleanup")
        assert count > 0, f"precondition: expected the coi-{ip} accept rule in open mode"

        _coi_stop(coi_binary, name)
        assert _count_rules_for_ip(ip) == 0, f"coi-{ip} accept rule should be gone after stop"

        start = subprocess.run(
            [coi_binary, "container", "start", name],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        assert start.returncode == 0, f"container start failed: {start.stderr}"
        new_ip, new_count = _wait_for_rules_for_ip(coi_binary, name)
        assert new_ip and new_count > 0, (
            f"coi container start should re-add the open-mode accept rule (ip={new_ip!r})"
        )
        assert _ip6_block_veths(name) == [], "open mode installs no IPv6 block"
    finally:
        os.unlink(config_file)
