"""
Integration test for #977: coi writes /etc/hosts when container root cannot.

A container from an OCI registry image gets /etc/hosts bind-mounted from the
instance directory, a file owned by host root, which the container's idmap does
not map: container root sees it as nobody:nogroup 0644 and cannot write it. coi
then bind-mounts a writable copy over it inside the container.

The test builds the same state on a coi container: it bind-mounts a file owned
by host root over /etc/hosts with a disk device.
"""

import subprocess
import tempfile
from pathlib import Path

import pytest

from support.helpers import calculate_container_name, exec_in

HOST_HOSTS = "127.0.0.1\tlocalhost\n"


def _sudo(*args):
    return subprocess.run(["sudo", "-n", *args], capture_output=True, text=True, timeout=30)


def _resolves(coi_binary, container_name, name, ip):
    """Whether name resolves to ip in the container. getent exits 2 when the
    name is not found; any other failure fails the test."""
    rc, out = exec_in(coi_binary, container_name, f"getent hosts {name}")
    assert rc in (0, 2), f"getent hosts {name} failed (exit {rc}): {out}"
    return rc == 0 and ip in out


def _coi_hosts(coi_binary, *args):
    result = subprocess.run(
        [coi_binary, "hosts", *args], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, (
        f"coi hosts {' '.join(args)} failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_hosts_written_when_container_root_cannot(coi_binary, cleanup_containers, workspace_dir):
    """`coi hosts add/remove` work on a container whose /etc/hosts is owned by
    unmapped host root, entries survive a restart, and the host file is not
    changed."""
    if _sudo("true").returncode != 0:
        pytest.skip("needs passwordless sudo to create a root-owned file")

    container_name = calculate_container_name(workspace_dir, 1)
    host_dir = Path(tempfile.mkdtemp(prefix="coi-hosts-977-"))
    host_file = host_dir / "hosts"
    host_file.write_text(HOST_HOSTS)
    assert _sudo("chown", "root:root", str(host_file)).returncode == 0

    launch = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert launch.returncode == 0, f"launch should succeed. stderr: {launch.stderr}"
    try:
        add_device = subprocess.run(
            [
                "incus",
                "config",
                "device",
                "add",
                container_name,
                "coi-test-hosts",
                "disk",
                f"source={host_file}",
                "path=/etc/hosts",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert add_device.returncode == 0, f"device add failed: {add_device.stderr}"

        # Precondition: container root cannot write /etc/hosts.
        rc, out = exec_in(coi_binary, container_name, "true >> /etc/hosts")
        assert rc != 0, f"container root should not be able to write /etc/hosts: {out}"

        _coi_hosts(coi_binary, "add", container_name, "8.8.8.8", "dns.test")
        assert _resolves(coi_binary, container_name, "dns.test", "8.8.8.8")
        assert _resolves(coi_binary, container_name, "localhost", "127.0.0.1"), (
            "the entries of the original file should be kept"
        )

        # Later writes go to the mounted copy.
        _coi_hosts(coi_binary, "add", container_name, "8.8.4.4", "dns2.test")
        _coi_hosts(coi_binary, "remove", container_name, "dns.test")
        assert _resolves(coi_binary, container_name, "dns2.test", "8.8.4.4")
        assert not _resolves(coi_binary, container_name, "dns.test", "8.8.8.8"), (
            "a removed entry should no longer resolve"
        )

        # A restart mounts the host file again; the next write keeps dns2.test.
        restart = subprocess.run(
            ["incus", "restart", container_name], capture_output=True, text=True, timeout=120
        )
        assert restart.returncode == 0, f"restart failed: {restart.stderr}"
        _coi_hosts(coi_binary, "add", container_name, "1.1.1.1", "dns3.test")
        assert _resolves(coi_binary, container_name, "dns3.test", "1.1.1.1")
        assert _resolves(coi_binary, container_name, "dns2.test", "8.8.4.4"), (
            "an entry added before the restart should be kept"
        )

        assert _sudo("cat", str(host_file)).stdout == HOST_HOSTS, (
            "the host file must not be changed"
        )
    finally:
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=60,
        )
        _sudo("rm", "-rf", str(host_dir))
