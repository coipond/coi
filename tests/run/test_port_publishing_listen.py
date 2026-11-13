"""
Test for coi run - the host listen address of published ports.

A published port's proxy device listens on 127.0.0.1 unless its
`[[ports.map]]` entry sets `listen`, so a sandbox service reaches the LAN
only when the user asks for it.

Tests that:
1. a map entry without `listen` binds the host's 127.0.0.1 only
2. `listen = "0.0.0.0"` is reachable on a non-loopback host address
3. `listen = "<interface IP>"` binds that address only
4. the pool stays on 127.0.0.1 even when a map entry uses 0.0.0.0
5. a `listen` value that is not an IP address fails the profile
6. a `listen` value that is not an IP address fails a config file

Each launch serves a sentinel over HTTP inside the container; the host
connects to the published port on each address. The ports come from a
trusted config ($COI_CONFIG).
"""

import socket
import subprocess
from pathlib import Path

from support.helpers import (
    NODE_PORT_SERVER,
    PORT_SENTINEL,
    calculate_container_name,
    container_device_get,
    fetch_host_port,
    free_host_port,
    workspace_containers,
    write_trusted_coi_config,
)


def _host_ip():
    """The host's non-loopback IPv4 address on its default route.

    A UDP connect only selects the route; it sends no packet.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
    assert not ip.startswith("127."), f"host has no non-loopback IPv4 address: {ip}"
    return ip


def _assert_refused(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
    except ConnectionRefusedError:
        return
    raise AssertionError(f"{host}:{port} accepted a connection; the port must not listen there")


def _device_listen(workspace_dir, device):
    container_name = calculate_container_name(workspace_dir, 1)
    listen = container_device_get(container_name, device, "listen")
    assert listen is not None, f"cannot read {device} of {container_name}"
    return listen


def _serve(coi_binary, workspace_dir, env, script):
    return subprocess.Popen(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=workspace_dir,
        env=env,
    )


def _stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()


def _web_entry(pin, listen=None):
    listen_line = f'listen = "{listen}"\n' if listen else ""
    return f"""
[[ports.map]]
name = "web"
container = 8000
host = {pin}
{listen_line}"""


def test_default_listen_is_loopback_only(coi_binary, cleanup_containers, workspace_dir):
    """A map entry without `listen` answers on 127.0.0.1, not on the host IP."""
    host_ip = _host_ip()
    pin = free_host_port("0.0.0.0")
    env = write_trusted_coi_config(_web_entry(pin))
    proc = _serve(coi_binary, workspace_dir, env, f"PORT=8000 {NODE_PORT_SERVER}")
    try:
        body = fetch_host_port(pin, timeout_total=90)
        assert PORT_SENTINEL in body, f"loopback fetch returned: {body!r}"
        assert _device_listen(workspace_dir, "coi-port-web") == f"tcp:127.0.0.1:{pin}"
        _assert_refused(host_ip, pin)
    finally:
        _stop(proc)


def test_listen_all_addresses_reachable_on_host_ip(coi_binary, cleanup_containers, workspace_dir):
    """`listen = "0.0.0.0"` publishes the port on the host's non-loopback IP."""
    host_ip = _host_ip()
    pin = free_host_port("0.0.0.0")
    env = write_trusted_coi_config(_web_entry(pin, "0.0.0.0"))
    proc = _serve(coi_binary, workspace_dir, env, f"PORT=8000 {NODE_PORT_SERVER}")
    try:
        body = fetch_host_port(pin, host=host_ip, timeout_total=90)
        assert PORT_SENTINEL in body, f"fetch on {host_ip} returned: {body!r}"
        assert _device_listen(workspace_dir, "coi-port-web") == f"tcp:0.0.0.0:{pin}"
    finally:
        _stop(proc)


def test_listen_interface_ip_binds_only_that_address(coi_binary, cleanup_containers, workspace_dir):
    """`listen = "<host IP>"` answers on that IP and not on 127.0.0.1."""
    host_ip = _host_ip()
    pin = free_host_port("0.0.0.0")
    env = write_trusted_coi_config(_web_entry(pin, host_ip))
    proc = _serve(coi_binary, workspace_dir, env, f"PORT=8000 {NODE_PORT_SERVER}")
    try:
        body = fetch_host_port(pin, host=host_ip, timeout_total=90)
        assert PORT_SENTINEL in body, f"fetch on {host_ip} returned: {body!r}"
        assert _device_listen(workspace_dir, "coi-port-web") == f"tcp:{host_ip}:{pin}"
        _assert_refused("127.0.0.1", pin)
    finally:
        _stop(proc)


def test_pool_stays_loopback(coi_binary, cleanup_containers, workspace_dir):
    """Pool ports listen on 127.0.0.1 even next to a map entry on 0.0.0.0."""
    host_ip = _host_ip()
    pin = free_host_port("0.0.0.0")
    env = write_trusted_coi_config("[ports]\npool = 1\n" + _web_entry(pin, "0.0.0.0"))
    proc = _serve(
        coi_binary,
        workspace_dir,
        env,
        f'PORT="${{COI_PORTS%% *}}" {NODE_PORT_SERVER} & PORT=8000 {NODE_PORT_SERVER}; wait',
    )
    try:
        body = fetch_host_port(pin, host=host_ip, timeout_total=90)
        assert PORT_SENTINEL in body, f"map entry fetch on {host_ip} returned: {body!r}"
        listen = _device_listen(workspace_dir, "coi-port-pool-1")
        assert listen.startswith("tcp:127.0.0.1:"), f"pool device must listen on loopback: {listen}"
        pool_port = int(listen.rsplit(":", 1)[1])
        body = fetch_host_port(pool_port, timeout_total=30)
        assert PORT_SENTINEL in body, f"pool fetch on 127.0.0.1 returned: {body!r}"
        _assert_refused(host_ip, pool_port)
    finally:
        _stop(proc)


def test_invalid_listen_fails_profile(coi_binary, cleanup_containers, workspace_dir):
    """A `listen` value that is not an IP address aborts before any container."""
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "badlisten"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        '[[ports.map]]\nname = "web"\ncontainer = 8000\nlisten = "localhost"\n'
    )
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--profile", "badlisten", "--", "true"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )
    assert result.returncode != 0, "coi run must fail on a non-IP listen value"
    assert "'listen' must be an IP address" in result.stderr, (
        f"error should name the invalid listen value. stderr: {result.stderr}"
    )
    assert not workspace_containers(workspace_dir), "invalid config must abort before launch"


def test_invalid_listen_fails_config_file(coi_binary, cleanup_containers, workspace_dir):
    """A non-IP `listen` in $COI_CONFIG aborts before any container."""
    env = write_trusted_coi_config(_web_entry(free_host_port(), "localhost"))
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "true"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
        env=env,
    )
    assert result.returncode != 0, "coi run must fail on a non-IP listen value"
    assert "'listen' must be an IP address" in result.stderr, (
        f"error should name the invalid listen value. stderr: {result.stderr}"
    )
    assert not workspace_containers(workspace_dir), "invalid config must abort before launch"
