"""
Integration tests for network allowlist mode.

Tests the domain allowlisting feature with DNS resolution and IP-based filtering.

Network isolation is implemented using nft rules.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from support.helpers import container_ipv4, wait_for_firewall_rules


def test_allowlist_mode_allows_specified_domains(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that allowlist mode allows access to domains in allowed_domains.

    Verifies that containers can reach domains explicitly listed in the allowlist.
    """
    # Create temporary config with allowlist
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",                 # DNS server (required for resolution)
    "1.1.1.1",                 # Cloudflare DNS
    "registry.npmjs.org",      # Test domain
]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        # Start container in background with allowlist mode
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

        # Extract container name from output (check both stdout and stderr)
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, f"Could not find container name in output: {output}"

        # Fix DNS in container (required for resolution)
        subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "echo 'nameserver 8.8.8.8' > /etc/resolv.conf",
            ],
            capture_output=True,
            timeout=10,
        )

        # Test: curl allowed domain (should work)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "curl",
                "-I",
                "-m",
                "10",
                "https://registry.npmjs.org",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        assert result.returncode == 0, f"Failed to reach allowed domain: {result.stderr}"
        assert "HTTP" in result.stderr, f"No HTTP response from allowed domain: {result.stderr}"

    finally:
        os.unlink(config_file)


def test_allowlist_blocks_non_allowed_domains(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that allowlist mode blocks domains NOT in allowed_domains.

    Verifies that containers cannot reach domains not explicitly listed.
    """
    # Create temporary config with minimal allowlist
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",                 # DNS server only
    "1.1.1.1",
    "registry.npmjs.org",      # Only this domain allowed
]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        # Start container in background
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

        # Extract container name (check both stdout and stderr)
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, "Could not find container name in output"

        # Fix DNS
        subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "echo 'nameserver 8.8.8.8' > /etc/resolv.conf",
            ],
            capture_output=True,
            timeout=10,
        )

        # Wait for firewall rules to be fully applied (poll for default-deny rule)
        assert wait_for_firewall_rules(container_name, timeout=30), (
            "Firewall default-deny rule was not applied in time"
        )

        # Test: curl blocked domain (should fail)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "timeout",
                "5",
                "curl",
                "-I",
                "-m",
                "5",
                "https://github.com",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # Should fail to connect (either REJECT with "Connection refused" or timeout)
        assert result.returncode != 0, (
            f"Should not reach blocked domain github.com: {result.stderr}"
        )
        # A blocked domain now fails EARLIER than it used to. It has no entry in the
        # container's /etc/hosts and DNS is denied, so curl cannot even resolve it
        # ("Could not resolve host", exit 6) and never gets as far as a refused
        # connection. Resolution failure, connection refusal and timeout are all
        # valid evidence the domain is blocked.
        is_unresolvable = (
            "Could not resolve host" in result.stderr or "exit status 6" in result.stderr
        )
        is_rejected = "Connection refused" in result.stderr or "Failed to connect" in result.stderr
        is_timeout = "exit status 124" in result.stderr or result.returncode == 124
        assert is_unresolvable or is_rejected or is_timeout, (
            f"Expected connection failure for blocked domain: {result.stderr}"
        )

        # Test: curl another blocked domain
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "timeout",
                "5",
                "curl",
                "-I",
                "-m",
                "5",
                "http://example.com",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode != 0, (
            f"Should not reach blocked domain example.com: {result.stderr}"
        )

    finally:
        os.unlink(config_file)


def test_allowlist_always_blocks_rfc1918(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that allowlist mode always blocks RFC1918 private networks.

    Even with domains in the allowlist, RFC1918 addresses should be blocked.
    """
    # Create temporary config
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",
    "1.1.1.1",
]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        # Start container
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

        # Extract container name (check both stdout and stderr)
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, "Could not find container name"

        # Test: RFC1918 10.0.0.0/8 (should be blocked)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "timeout",
                "3",
                "curl",
                "-I",
                "-m",
                "3",
                "http://10.0.0.1",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        assert result.returncode != 0, f"Should block RFC1918 10.0.0.1: {result.stderr}"

        # Test: RFC1918 192.168.0.0/16 (should be blocked)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "timeout",
                "3",
                "curl",
                "-I",
                "-m",
                "3",
                "http://192.168.1.1",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        assert result.returncode != 0, f"Should block RFC1918 192.168.1.1: {result.stderr}"

        # Test: RFC1918 172.16.0.0/12 (should be blocked)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "timeout",
                "3",
                "curl",
                "-I",
                "-m",
                "3",
                "http://172.16.0.1",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        assert result.returncode != 0, f"Should block RFC1918 172.16.0.1: {result.stderr}"

    finally:
        os.unlink(config_file)


def test_allowlist_blocks_public_ips_not_in_list(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that allowlist mode blocks public IPs not in the allowlist.

    Verifies that nft's default-deny rules block non-allowed public IPs.
    """
    # Create temporary config with only DNS
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",    # Only DNS allowed
    "1.1.1.1",
]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        # Start container
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

        # Extract container name (check both stdout and stderr)
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, "Could not find container name"

        # Test: Random public IP not in allowlist (should be blocked by implicit default-deny)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "timeout",
                "3",
                "curl",
                "-I",
                "-m",
                "3",
                "http://9.9.9.9",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        assert result.returncode != 0, (
            f"Should block non-allowed public IP 9.9.9.9: {result.stderr}"
        )
        # Accept either explicit rejection or timeout (exit code 124) as valid blocking
        is_rejected = "Connection refused" in result.stderr or "Failed to connect" in result.stderr
        is_timeout = "exit status 124" in result.stderr or result.returncode == 124
        assert is_rejected or is_timeout, (
            f"Expected connection failure for non-allowed IP: {result.stderr}"
        )

    finally:
        os.unlink(config_file)


def test_allowlist_allows_host_to_access_container_services(
    coi_binary, workspace_dir, cleanup_containers
):
    """
    Test that host can access services running in container (established connections).

    When a service like Puma or HTTP server runs in the container, the host should
    be able to access it because established/related connections back to the host
    are allowed via connection tracking.
    """
    # Create temporary config with allowlist
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(
            """
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",
    "1.1.1.1",
]
refresh_interval_minutes = 30
"""
        )
        config_file = f.name

    try:
        # Start container in background
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

        # Extract container name (check both stdout and stderr)
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, "Could not find container name"

        # Start a simple HTTP server in the container on port 8000
        subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "nohup python3 -m http.server 8000 > /tmp/http-server.log 2>&1 &",
            ],
            capture_output=True,
            timeout=10,
        )

        # Give server time to start
        time.sleep(2)

        # Get container's IP address using incus list (more reliable than hostname -I)
        result = subprocess.run(
            ["incus", "list", container_name, "--format=json"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"Failed to get container info: {result.stderr}"

        container_info = json.loads(result.stdout)[0]
        # Get IPv4 address from eth0 interface
        container_ip = container_info["state"]["network"]["eth0"]["addresses"][0]["address"]

        # Test: Host should be able to access the HTTP server
        # This verifies established connection tracking works
        result = subprocess.run(
            ["curl", "-I", "-m", "5", f"http://{container_ip}:8000"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, (
            f"Host should be able to access container service: {result.stderr}"
        )
        assert "HTTP" in result.stdout, f"Expected HTTP response from container: {result.stdout}"

    finally:
        os.unlink(config_file)


def test_restricted_allows_host_to_access_container_services(
    coi_binary, workspace_dir, cleanup_containers
):
    """
    Test that host can access services in restricted mode too.

    Verifies that the established connection rule works in both allowlist
    and restricted network modes.
    """
    # Configure restricted network mode via workspace config file
    config_dir = pathlib.Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text('[network]\nmode = "restricted"\n')

    # Start container in background with restricted mode
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
    )

    assert result.returncode == 0, f"Failed to start container: {result.stderr}"

    # Extract container name (check both stdout and stderr)
    container_name = None
    output = result.stdout + result.stderr
    for line in output.split("\n"):
        if "Container: " in line:
            container_name = line.split("Container: ")[1].strip()
            break

    assert container_name, "Could not find container name"

    # Start a simple HTTP server in the container on port 8000
    subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "nohup python3 -m http.server 8000 > /tmp/http-server.log 2>&1 &",
        ],
        capture_output=True,
        timeout=10,
    )

    # Give server time to start
    time.sleep(2)

    # Get container's IP address using incus list (more reliable than hostname -I)
    result = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, f"Failed to get container info: {result.stderr}"

    container_info = json.loads(result.stdout)[0]
    # Get IPv4 address from eth0 interface
    container_ip = container_info["state"]["network"]["eth0"]["addresses"][0]["address"]

    # Test: Host should be able to access the HTTP server
    result = subprocess.run(
        ["curl", "-I", "-m", "5", f"http://{container_ip}:8000"],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, (
        f"Host should be able to access container service: {result.stderr}"
    )
    assert "HTTP" in result.stdout, f"Expected HTTP response from container: {result.stdout}"


def test_allowlist_rules_are_l4_scoped(coi_binary, workspace_dir, cleanup_containers):
    """Allowlist accept rules must be scoped to TCP/UDP + rate-limited ICMP echo (M4).

    Without L4 scoping, any protocol (raw IP, ICMP flood, GRE, ...) to an allowed
    IP is permitted — a covert exfil channel allowlist mode is meant to prevent.
    This asserts the emitted nft rules carry the L4 constraints; legitimate
    TCP/UDP egress to allowed hosts is covered by
    test_allowlist_mode_allows_specified_domains.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1"]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        result = subprocess.run(
            [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
            capture_output=True,
            text=True,
            timeout=90,
            env=env,
        )
        assert result.returncode == 0, f"Failed to start container: {result.stderr}"

        container_name = None
        for line in (result.stdout + result.stderr).split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break
        assert container_name, f"Could not find container name: {result.stdout + result.stderr}"

        # Rule application is asynchronous; poll like the other allowlist tests.
        assert wait_for_firewall_rules(container_name, timeout=30), (
            f"firewall rules not applied for {container_name}"
        )

        # Allowed addresses live in the container's nft sets, and the accept rules
        # reference those sets by name rather than naming each address. So the L4
        # scoping is asserted on the rules that admit the sets — and the address
        # itself is asserted to be in a set, which is what those rules admit.
        ip = container_ipv4(container_name)
        assert ip, f"could not determine the IP of {container_name}"
        ident = ip.replace(".", "_")

        chain = subprocess.run(
            ["sudo", "-n", "nft", "list", "chain", "ip", "coi", "forward"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Scope the assertions to the rule line(s) for THIS container, not the whole
        # shared chain — otherwise a leftover/concurrent allowlist rule could satisfy
        # the substrings even if this container's rules were emitted unscoped.
        # Two families of set-admitting rules: the port-scoped sets (coi_sp_/coi_dp_)
        # back the L4 (TCP/UDP) accepts, and the address-only sets (coi_s_/coi_d_)
        # back the rate-limited ICMP echo. Match all of them.
        set_rules = [
            ln
            for ln in chain.stdout.splitlines()
            if any(f"@coi_{p}_{ident}" in ln for p in ("s", "d", "sp", "dp"))
        ]
        assert set_rules, f"no allowlist set rules for {ip}:\n{chain.stdout}"
        joined = "\n".join(set_rules)
        assert "l4proto" in joined, (
            f"expected TCP/UDP (l4proto) scoping on the allowlist set rules:\n{joined}"
        )
        assert "echo-request" in joined and "10/second" in joined, (
            f"expected rate-limited (10/second) ICMP echo on the allowlist set rules:\n{joined}"
        )

        # And the configured address must actually be in the static set those rules
        # admit — otherwise the scoping above would be guarding nothing.
        static_set = subprocess.run(
            ["sudo", "-n", "nft", "list", "set", "ip", "coi", f"coi_s_{ident}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "1.1.1.1" in static_set.stdout, (
            f"1.1.1.1 is allowlisted but not in the static set:\n{static_set.stdout}"
        )
    finally:
        os.unlink(config_file)
