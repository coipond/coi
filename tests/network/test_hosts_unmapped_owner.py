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

from support.helpers import calculate_container_name

HOST_HOSTS = "127.0.0.1\tlocalhost\n"


def _sudo(*args):
    return subprocess.run(["sudo", "-n", *args], capture_output=True, text=True, timeout=30)


def _getent(coi_binary, container_name, name):
    return subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "getent", "hosts", name],
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout


def _coi_hosts(coi_binary, *args):
    result = subprocess.run(
        [coi_binary, "hosts", *args], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, (
        f"coi hosts {' '.join(args)} failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_hosts_written_when_container_root_cannot(coi_binary, cleanup_containers, workspace_dir):
    """`coi hosts add/remove` work on a container whose /etc/hosts is owned by
    unmapped host root; the host file is not changed."""
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
        probe = subprocess.run(
            ["incus", "exec", container_name, "--", "sh", "-c", "true >> /etc/hosts"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert probe.returncode != 0, "container root should not be able to write /etc/hosts"

        _coi_hosts(coi_binary, "add", container_name, "8.8.8.8", "dns.test")
        assert "8.8.8.8" in _getent(coi_binary, container_name, "dns.test"), (
            "dns.test should resolve to 8.8.8.8 in the container"
        )
        assert "127.0.0.1" in _getent(coi_binary, container_name, "localhost"), (
            "the entries of the original file should be kept"
        )

        # Later writes go to the mounted copy.
        _coi_hosts(coi_binary, "add", container_name, "8.8.4.4", "dns2.test")
        _coi_hosts(coi_binary, "remove", container_name, "dns.test")
        assert "8.8.4.4" in _getent(coi_binary, container_name, "dns2.test")
        assert "8.8.8.8" not in _getent(coi_binary, container_name, "dns.test"), (
            "a removed entry should no longer resolve"
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
