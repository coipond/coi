"""
Integration tests for IPv6 disabling in network-isolated modes.

All firewall rules are IPv4-only. IPv6 would bypass them entirely, so Coi
disables IPv6 inside the container for restricted and allowlist modes.
Open mode does not apply firewall rules, so IPv6 is left enabled.
"""

import os
import subprocess
import tempfile
import time


def _start_background_container(coi_binary, workspace_dir, network_mode, config_extra=""):
    """Start a container in background with the given network mode and return its name."""
    config_content = f"""
[network]
mode = "{network_mode}"
{config_extra}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(config_content)
        config_file = f.name

    env = os.environ.copy()
    env["COI_CONFIG"] = config_file

    result = subprocess.run(
        [
            coi_binary,
            "shell",
            "--workspace",
            workspace_dir,
            "--background",
        ],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )

    assert result.returncode == 0, f"Failed to start container: {result.stderr}"

    container_name = None
    output = result.stdout + result.stderr
    for line in output.split("\n"):
        if "Container: " in line:
            container_name = line.split("Container: ")[1].strip()
            break

    assert container_name, f"Could not find container name in output: {output}"

    return container_name, config_file


def _get_sysctl_value(coi_binary, container_name, sysctl_key):
    """Read a sysctl value from inside the container."""
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "sysctl",
            "-n",
            sysctl_key,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result


def test_ipv6_disabled_in_restricted_mode(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that IPv6 is disabled inside containers running in RESTRICTED mode.

    All firewall rules are IPv4-only. Without disabling IPv6, a process inside
    the container could use IPv6 to bypass all network restrictions.
    """
    container_name, config_file = _start_background_container(
        coi_binary, workspace_dir, "restricted"
    )

    try:
        # Check net.ipv6.conf.all.disable_ipv6
        result = _get_sysctl_value(coi_binary, container_name, "net.ipv6.conf.all.disable_ipv6")
        assert result.returncode == 0, f"Failed to read sysctl: {result.stderr}"
        value = result.stderr.strip()
        assert value == "1", (
            f"IPv6 should be disabled (net.ipv6.conf.all.disable_ipv6=1) "
            f"in restricted mode, got: {value}"
        )

        # Check net.ipv6.conf.default.disable_ipv6
        result = _get_sysctl_value(coi_binary, container_name, "net.ipv6.conf.default.disable_ipv6")
        assert result.returncode == 0, f"Failed to read sysctl: {result.stderr}"
        value = result.stderr.strip()
        assert value == "1", (
            f"IPv6 should be disabled (net.ipv6.conf.default.disable_ipv6=1) "
            f"in restricted mode, got: {value}"
        )
    finally:
        os.unlink(config_file)


def test_ipv6_disabled_in_allowlist_mode(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that IPv6 is disabled inside containers running in ALLOWLIST mode.

    Allowlist mode only creates IPv4 firewall rules. Without disabling IPv6,
    a process could bypass the allowlist entirely via IPv6 connectivity.
    """
    container_name, config_file = _start_background_container(
        coi_binary,
        workspace_dir,
        "allowlist",
        config_extra='allowed_domains = ["example.com"]',
    )

    try:
        # Check net.ipv6.conf.all.disable_ipv6
        result = _get_sysctl_value(coi_binary, container_name, "net.ipv6.conf.all.disable_ipv6")
        assert result.returncode == 0, f"Failed to read sysctl: {result.stderr}"
        value = result.stderr.strip()
        assert value == "1", (
            f"IPv6 should be disabled (net.ipv6.conf.all.disable_ipv6=1) "
            f"in allowlist mode, got: {value}"
        )

        # Check net.ipv6.conf.default.disable_ipv6
        result = _get_sysctl_value(coi_binary, container_name, "net.ipv6.conf.default.disable_ipv6")
        assert result.returncode == 0, f"Failed to read sysctl: {result.stderr}"
        value = result.stderr.strip()
        assert value == "1", (
            f"IPv6 should be disabled (net.ipv6.conf.default.disable_ipv6=1) "
            f"in allowlist mode, got: {value}"
        )
    finally:
        os.unlink(config_file)


def test_ipv6_not_disabled_in_open_mode(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that IPv6 is NOT disabled in OPEN mode containers.

    Open mode does not apply firewall rules, so there is no IPv6 bypass risk.
    IPv6 should remain enabled for full connectivity.
    """
    container_name, config_file = _start_background_container(coi_binary, workspace_dir, "open")

    try:
        # Check net.ipv6.conf.all.disable_ipv6 — should be 0 (enabled)
        result = _get_sysctl_value(coi_binary, container_name, "net.ipv6.conf.all.disable_ipv6")
        assert result.returncode == 0, f"Failed to read sysctl: {result.stderr}"
        value = result.stderr.strip()
        assert value == "0", (
            f"IPv6 should NOT be disabled in open mode "
            f"(net.ipv6.conf.all.disable_ipv6 should be 0), got: {value}"
        )
    finally:
        os.unlink(config_file)


def _nft_ip6_coi_forward():
    """Return the host-side ``ip6 coi forward`` chain text (empty if absent)."""
    result = subprocess.run(
        ["sudo", "-n", "nft", "-a", "list", "chain", "ip6", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.stdout if result.returncode == 0 else ""


def _wait_for_ip6_drop(container_name, timeout=20):
    """Poll until the per-container host-side IPv6 drop rule appears."""
    comment = f"coi6-{container_name}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if comment in _nft_ip6_coi_forward():
            return True
        time.sleep(0.5)
    return False


def test_ipv6_host_drop_present_in_restricted_mode(coi_binary, workspace_dir, cleanup_containers):
    """
    RESTRICTED mode must install a HOST-SIDE IPv6 drop rule.

    The in-container disable_ipv6 sysctl is reversible by in-container root, so
    the enforced boundary is a drop rule in the host's ``ip6 coi forward`` chain
    keyed on the container's veth — which the container cannot touch.
    """
    container_name, config_file = _start_background_container(
        coi_binary, workspace_dir, "restricted"
    )
    try:
        assert _wait_for_ip6_drop(container_name), (
            f"host-side IPv6 drop (coi6-{container_name}) not found in ip6 coi forward "
            f"chain:\n{_nft_ip6_coi_forward()}"
        )
        chain = _nft_ip6_coi_forward()
        assert "drop" in chain, f"expected a drop action in ip6 coi forward:\n{chain}"
        assert "iifname" in chain, f"expected an iifname match in ip6 coi forward:\n{chain}"
    finally:
        os.unlink(config_file)


def test_ipv6_host_drop_present_in_allowlist_mode(coi_binary, workspace_dir, cleanup_containers):
    """ALLOWLIST mode must also install the host-side IPv6 drop rule."""
    container_name, config_file = _start_background_container(
        coi_binary,
        workspace_dir,
        "allowlist",
        config_extra='allowed_domains = ["example.com"]',
    )
    try:
        assert _wait_for_ip6_drop(container_name), (
            f"host-side IPv6 drop (coi6-{container_name}) not found in allowlist mode:\n"
            f"{_nft_ip6_coi_forward()}"
        )
    finally:
        os.unlink(config_file)


def test_ipv6_host_drop_absent_in_open_mode(coi_binary, workspace_dir, cleanup_containers):
    """
    OPEN mode opts into unrestricted egress, so it must NOT install the
    per-container host-side IPv6 drop rule.
    """
    container_name, config_file = _start_background_container(coi_binary, workspace_dir, "open")
    try:
        # Open-mode setup completes before `coi shell --background` returns; give a
        # brief margin, then confirm no per-container IPv6 drop was installed.
        time.sleep(3)
        assert f"coi6-{container_name}" not in _nft_ip6_coi_forward(), (
            "open mode should not install a host-side IPv6 drop rule"
        )
    finally:
        os.unlink(config_file)


def test_ipv6_socket_fails_in_restricted_mode(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that IPv6 network connections fail in RESTRICTED mode.

    Even if a process tries to use IPv6 addresses directly, the disabled
    IPv6 stack should prevent any communication.
    """
    container_name, config_file = _start_background_container(
        coi_binary, workspace_dir, "restricted"
    )

    try:
        # Attempt to use IPv6 — should fail because the stack is disabled
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "curl",
                "-6",
                "-s",
                "-m",
                "5",
                "http://example.com",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        # curl -6 should fail when IPv6 is disabled
        assert result.returncode != 0, (
            f"IPv6 connection should fail in restricted mode but succeeded: {result.stderr}"
        )
    finally:
        os.unlink(config_file)
