"""
Test for coi network modes - container traffic to the host's own addresses.

Traffic a container sends to the host itself (the bridge gateway, or any other
host address) is delivered through the host's input path, not the forward chain.

Tests that:
1. restricted and allowlist mode refuse a listener on the gateway address
2. restricted mode still resolves names; both modes still renew the DHCP lease
3. an allowed_domains entry naming a host address opens only its port
4. open mode and allow_host_access still reach the host
5. the container's input rules are removed when it stops or is killed

Each test starts its own HTTP listener on the gateway address.
"""

import contextlib
import pathlib
import re
import socket
import subprocess
import sys
import time

from support.helpers import (
    container_ipv4,
    extract_container_name,
    wait_for_firewall_rules,
    write_trusted_coi_config,
)


def _launch(coi_binary, workspace_dir, project_config=None, env=None):
    if project_config is not None:
        config_dir = pathlib.Path(workspace_dir) / ".coi"
        config_dir.mkdir(exist_ok=True)
        (config_dir / "config.toml").write_text(project_config)
    result = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background", "--debug"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, f"Shell should start. stderr: {result.stderr}"
    name = extract_container_name(result)
    assert name, f"Should find container name. stderr: {result.stderr}"
    wait_for_firewall_rules(name)
    return name


def _exec(coi_binary, name, *cmd, timeout=30):
    return subprocess.run(
        [coi_binary, "container", "exec", name, "--", *cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _gateway(coi_binary, name):
    r = _exec(coi_binary, name, "ip", "route", "show", "default")
    m = re.search(r"default via (\S+)", r.stdout + r.stderr)
    assert m, f"Should find the gateway. Got: {r.stdout}{r.stderr}"
    return m.group(1)


def _free_port(addr):
    with socket.socket() as s:
        s.bind((addr, 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def _listener(addr, port):
    """An HTTP listener on addr:port on the host."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", addr],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with contextlib.suppress(OSError), socket.create_connection((addr, port), timeout=1):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"listener on {addr}:{port} did not come up")
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def _reaches(coi_binary, name, addr, port):
    r = _exec(
        coi_binary,
        name,
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "--connect-timeout",
        "3",
        f"http://{addr}:{port}/",
    )
    return r.returncode == 0


def _input_chain():
    return subprocess.run(
        ["sudo", "-n", "nft", "list", "chain", "ip", "coi", "input"],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout


def _assert_dhcp_renews(coi_binary, name):
    """The renewal resets the lease. Without it the lease only counts down, so
    compare with what is left when no renewal happens (before - elapsed)."""

    def lease_left():
        r = _exec(coi_binary, name, "ip", "-4", "-o", "addr", "show", "eth0")
        m = re.search(r"valid_lft (\d+)sec", r.stdout + r.stderr)
        assert m, f"eth0 should have a DHCP lease. Got: {r.stdout}{r.stderr}"
        return int(m.group(1))

    before = lease_left()
    start = time.monotonic()
    time.sleep(8)
    r = _exec(coi_binary, name, "networkctl", "renew", "eth0")
    assert r.returncode == 0, f"networkctl renew failed: {r.stderr}"
    time.sleep(3)
    after = lease_left()
    without_renewal = before - int(time.monotonic() - start)
    assert after >= without_renewal + 3, (
        f"DHCP renewal must reach the gateway and reset the lease: {after}s left, "
        f"{without_renewal}s expected without a renewal (was {before}s)"
    )


def test_restricted_refuses_host_listener(coi_binary, workspace_dir, cleanup_containers):
    """restricted mode: the gateway listener is refused; DNS and DHCP still work."""
    name = _launch(coi_binary, workspace_dir, '[network]\nmode = "restricted"\n')
    gw = _gateway(coi_binary, name)
    port = _free_port(gw)
    with _listener(gw, port):
        assert not _reaches(coi_binary, name, gw, port), (
            f"restricted container must not reach host listener {gw}:{port}"
        )

    r = _exec(coi_binary, name, "getent", "hosts", "github.com")
    assert r.returncode == 0, f"restricted mode must still resolve names. Got: {r.stderr}"

    _assert_dhcp_renews(coi_binary, name)


def test_allowlist_refuses_host_listener(coi_binary, workspace_dir, cleanup_containers):
    """allowlist mode: the gateway listener is refused; DHCP still renews."""
    name = _launch(
        coi_binary,
        workspace_dir,
        '[network]\nmode = "allowlist"\nallowed_domains = ["1.1.1.1:443"]\n',
    )
    gw = _gateway(coi_binary, name)
    port = _free_port(gw)
    with _listener(gw, port):
        assert not _reaches(coi_binary, name, gw, port), (
            f"allowlist container must not reach host listener {gw}:{port}"
        )

    _assert_dhcp_renews(coi_binary, name)


def _host_gateway():
    bridge = subprocess.run(
        ["incus", "profile", "device", "get", "default", "eth0", "network"],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    addr = subprocess.run(
        ["incus", "network", "get", bridge, "ipv4.address"],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    assert addr, f"Should find the IPv4 address of bridge {bridge!r}"
    return addr.split("/")[0]


def test_allowlist_host_address_entry_opens_its_port(coi_binary, workspace_dir, cleanup_containers):
    """allowlist mode: an allowed_domains entry naming the gateway opens only its port."""
    gw = _host_gateway()
    allowed = _free_port(gw)
    other = _free_port(gw)
    while other == allowed:
        other = _free_port(gw)
    name = _launch(
        coi_binary,
        workspace_dir,
        f'[network]\nmode = "allowlist"\nallowed_domains = ["{gw}:{allowed}"]\n',
    )
    assert _gateway(coi_binary, name) == gw
    with _listener(gw, allowed), _listener(gw, other):
        assert _reaches(coi_binary, name, gw, allowed), f"{gw}:{allowed} is allowlisted"
        assert not _reaches(coi_binary, name, gw, other), f"{gw}:{other} is not allowlisted"


def test_open_mode_reaches_host_listener(coi_binary, workspace_dir, cleanup_containers):
    """open mode is unchanged: the gateway listener is reachable."""
    env = write_trusted_coi_config('[network]\nmode = "open"\n')
    name = _launch(coi_binary, workspace_dir, env=env)
    gw = _gateway(coi_binary, name)
    port = _free_port(gw)
    with _listener(gw, port):
        assert _reaches(coi_binary, name, gw, port), f"open container must reach {gw}:{port}"


def test_allow_host_access_reaches_host_listener(coi_binary, workspace_dir, cleanup_containers):
    """restricted mode with allow_host_access: the gateway listener is reachable."""
    env = write_trusted_coi_config('[network]\nmode = "restricted"\nallow_host_access = true\n')
    name = _launch(coi_binary, workspace_dir, env=env)
    gw = _gateway(coi_binary, name)
    port = _free_port(gw)
    with _listener(gw, port):
        assert _reaches(coi_binary, name, gw, port), (
            f"allow_host_access container must reach {gw}:{port}"
        )


def test_input_rules_removed_on_stop(coi_binary, workspace_dir, cleanup_containers):
    """The container's input rules exist while it runs and are gone after stop."""
    name = _launch(coi_binary, workspace_dir, '[network]\nmode = "restricted"\n')
    ip = container_ipv4(name)
    assert ip, f"Should find the IP of {name}"
    comment = f'comment "coi-{ip}"'
    assert comment in _input_chain(), f"input rules for {ip} should be installed"

    r = subprocess.run(
        [coi_binary, "container", "stop", name], capture_output=True, text=True, timeout=120
    )
    assert r.returncode == 0, f"stop failed: {r.stderr}"
    assert comment not in _input_chain(), f"input rules for {ip} should be removed on stop"


def test_input_rules_removed_on_kill(coi_binary, workspace_dir, cleanup_containers):
    """`coi kill` (the kill and orphan cleanup path) removes the input rules too."""
    name = _launch(coi_binary, workspace_dir, '[network]\nmode = "restricted"\n')
    ip = container_ipv4(name)
    assert ip, f"Should find the IP of {name}"
    comment = f'comment "coi-{ip}"'
    assert comment in _input_chain(), f"input rules for {ip} should be installed"

    r = subprocess.run(
        [coi_binary, "kill", "--force", name], capture_output=True, text=True, timeout=120
    )
    assert r.returncode == 0, f"kill failed: {r.stderr}"
    assert comment not in _input_chain(), f"input rules for {ip} should be removed on kill"
