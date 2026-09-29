"""
Integration tests for bridge-NIC hardening (anti-spoofing + port isolation).

Coi's egress rules match the container's source IP in an accept-policy nft chain,
so without NIC anti-spoofing an in-container root could add a second source IP
(or spoof its MAC) and bypass restricted/allowlist filtering. Separately,
same-bridge traffic to sibling containers is L2-switched and never traverses the
firewall, so it needs L2 port isolation. Coi sets security.ipv4_filtering,
security.mac_filtering and security.port_isolation on eth0 before first boot
(container.EnableNICSecurity).
"""

import json
import os
import subprocess
import tempfile
import time

import pytest


def _start_background_container(coi_binary, workspace_dir, network_mode, config_extra=""):
    """Start a container in background with the given network mode; return its name."""
    config_content = f'\n[network]\nmode = "{network_mode}"\n{config_extra}\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(config_content)
        config_file = f.name

    env = os.environ.copy()
    env["COI_CONFIG"] = config_file

    result = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert result.returncode == 0, f"Failed to start container: {result.stderr}"

    container_name = None
    for line in (result.stdout + result.stderr).split("\n"):
        if "Container: " in line:
            container_name = line.split("Container: ")[1].strip()
            break
    assert container_name, (
        f"Could not find container name in output: {result.stdout + result.stderr}"
    )
    return container_name, config_file


def _exec(coi_binary, container_name, argv, timeout=20):
    """Run a command inside the container (coi writes exec output to stderr)."""
    return subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _container_ipv4(container_name):
    """Return the container's eth0 IPv4 address, or None."""
    result = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    info = json.loads(result.stdout)
    if not info:
        return None
    addrs = info[0].get("state", {}).get("network", {}).get("eth0", {}).get("addresses", [])
    for addr in addrs:
        if addr.get("family") == "inet":
            return addr["address"]
    return None


def _device_key(container_name, key):
    """Read an eth0 device config key (e.g. security.ipv4_filtering)."""
    result = subprocess.run(
        ["incus", "config", "device", "get", container_name, "eth0", key],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.stdout.strip()


def test_nic_anti_spoof_keys_set_in_restricted_mode(coi_binary, workspace_dir, cleanup_containers):
    """eth0 must have ipv4_filtering, mac_filtering and port_isolation enabled."""
    container_name, config_file = _start_background_container(
        coi_binary, workspace_dir, "restricted"
    )
    try:
        for key in (
            "security.ipv4_filtering",
            "security.mac_filtering",
            "security.port_isolation",
        ):
            value = _device_key(container_name, key)
            assert value == "true", f"eth0 {key} should be 'true', got {value!r}"
    finally:
        os.unlink(config_file)


def test_source_ip_spoofing_blocked_in_restricted_mode(
    coi_binary, workspace_dir, cleanup_containers
):
    """Egress sourced from a non-leased IP must be dropped by NIC anti-spoofing."""
    container_name, config_file = _start_background_container(
        coi_binary, workspace_dir, "restricted"
    )
    try:
        # Baseline: restricted mode permits public internet from the real (leased) IP.
        baseline = _exec(
            coi_binary,
            container_name,
            ["curl", "-s", "-o", "/dev/null", "--connect-timeout", "5", "https://1.1.1.1"],
        )
        if baseline.returncode != 0:
            pytest.skip("no baseline internet egress in this environment")

        real_ip = _container_ipv4(container_name)
        if not real_ip:
            pytest.skip("could not determine container IPv4")
        spoof_ip = real_ip.rsplit(".", 1)[0] + ".250"
        if spoof_ip == real_ip:
            pytest.skip("could not derive a distinct spoof IP")

        added = _exec(
            coi_binary,
            container_name,
            ["sudo", "ip", "addr", "add", f"{spoof_ip}/24", "dev", "eth0"],
        )
        if added.returncode != 0:
            pytest.skip(f"could not add a secondary IP: {added.stderr}")

        # Egress bound to the spoofed source should be dropped at the bridge port.
        spoofed = _exec(
            coi_binary,
            container_name,
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "--interface",
                spoof_ip,
                "--connect-timeout",
                "5",
                "https://1.1.1.1",
            ],
        )
        assert spoofed.returncode != 0, (
            f"egress from spoofed source {spoof_ip} succeeded; NIC anti-spoofing not effective"
        )
    finally:
        os.unlink(config_file)


def test_sibling_container_isolation_in_restricted_mode(
    coi_binary, workspace_dir, cleanup_containers
):
    """A container must not reach a sibling on the same bridge (port isolation)."""
    c1, cfg1 = _start_background_container(coi_binary, workspace_dir, "restricted")
    cfg2 = None
    try:
        c2, cfg2 = _start_background_container(coi_binary, workspace_dir, "restricted")
        if c2 == c1:
            pytest.skip("could not start a distinct second container")

        ip2 = _container_ipv4(c2)
        if not ip2:
            pytest.skip("could not determine sibling IPv4")

        # Start a listener on the sibling using system Node.js (always present in the image).
        node_js = "require('http').createServer((q,s)=>s.end('ok')).listen(8099,'0.0.0.0')"
        node_server = f'setsid node -e "{node_js}" >/dev/null 2>&1 </dev/null &'
        _exec(coi_binary, c2, ["bash", "-c", node_server])

        # Sanity: the listener must answer on the sibling's own loopback before we
        # can meaningfully assert it is unreachable from the peer.
        listener_up = False
        for _ in range(12):
            local = _exec(coi_binary, c2, ["curl", "-s", "-m", "2", "http://127.0.0.1:8099"])
            if "ok" in (local.stdout + local.stderr):
                listener_up = True
                break
            time.sleep(0.5)
        if not listener_up:
            pytest.skip("sibling listener did not come up; cannot test isolation")

        # From c1 the sibling must be unreachable — port isolation drops it at L2.
        cross = _exec(coi_binary, c1, ["curl", "-s", "-m", "4", f"http://{ip2}:8099"])
        assert "ok" not in (cross.stdout + cross.stderr), (
            f"container {c1} reached sibling {c2} at {ip2}:8099 despite port isolation"
        )
    finally:
        os.unlink(cfg1)
        if cfg2:
            os.unlink(cfg2)
