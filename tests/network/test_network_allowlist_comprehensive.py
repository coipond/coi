"""
Integration tests for network ALLOWLIST mode.

Tests that ALLOWLIST mode implements default-deny behavior, only allowing
access to explicitly specified domains and IPs.

Network isolation is implemented using nft rules.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from support.helpers import wait_for_firewall_rules


def test_allowlist_allows_specified_domains(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that ALLOWLIST mode allows access to explicitly listed domains.

    Verifies that containers can reach domains in the allowed_domains list.
    """
    # Create temporary config with ALLOWLIST mode
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
        # Start container in background with ALLOWLIST mode
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

        # Extract container name from output
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
                "-s",
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


def test_allowlist_blocks_non_allowed(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that ALLOWLIST mode blocks domains NOT in allowed_domains.

    Verifies default-deny behavior for non-allowlisted domains.
    """
    # Create temporary config with minimal ALLOWLIST
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",                 # DNS server only
]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        # Start container in background with ALLOWLIST mode
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

        # Extract container name from output
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, f"Could not find container name in output: {output}"

        # Fix DNS in container
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

        # Test: curl example.com (NOT in allowlist, should fail)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "curl",
                "-s",
                "-m",
                "5",
                "http://example.com",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # Connection should fail (blocked)
        assert result.returncode != 0, f"Non-allowed domain should be blocked: {result.stderr}"

        # Test: curl github.com (NOT in allowlist, should fail)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "curl",
                "-s",
                "-m",
                "5",
                "https://github.com",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # Connection should fail (blocked)
        assert result.returncode != 0, f"Non-allowed domain should be blocked: {result.stderr}"

    finally:
        os.unlink(config_file)


def test_allowlist_blocks_rfc1918_always(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that ALLOWLIST mode blocks RFC1918 addresses regardless of allowlist.

    Verifies that RFC1918 blocking takes precedence over allowlist entries.
    """
    # Create temporary config with ALLOWLIST mode
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",
    "10.0.0.1",        # RFC1918 - should still be blocked
    "192.168.1.1",     # RFC1918 - should still be blocked
]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        # Start container in background with ALLOWLIST mode
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

        # Extract container name from output
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, f"Could not find container name in output: {output}"

        # Wait for firewall rules to be fully applied (poll for default-deny rule)
        assert wait_for_firewall_rules(container_name, timeout=30), (
            "Firewall default-deny rule was not applied in time"
        )

        # Test: attempt connection to 10.0.0.1 (even though in allowlist)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "curl",
                "-s",
                "-m",
                "5",
                "http://10.0.0.1",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # Connection should fail (RFC1918 blocking takes precedence)
        assert result.returncode != 0, (
            f"RFC1918 should be blocked even in allowlist: {result.stderr}"
        )

        # Test: attempt connection to 192.168.1.1 (even though in allowlist)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "curl",
                "-s",
                "-m",
                "5",
                "http://192.168.1.1",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # Connection should fail (RFC1918 blocking takes precedence)
        assert result.returncode != 0, (
            f"RFC1918 should be blocked even in allowlist: {result.stderr}"
        )

    finally:
        os.unlink(config_file)


def test_allowlist_dns_resolution(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that DNS resolution works in ALLOWLIST mode with allowed DNS servers.

    Verifies that containers can perform DNS queries to allowlisted DNS servers.
    """
    # Create temporary config with ALLOWLIST mode
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",                 # Google DNS
    "1.1.1.1",                 # Cloudflare DNS
]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        # Start container in background with ALLOWLIST mode
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

        # Extract container name from output
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, f"Could not find container name in output: {output}"

        # Test: nslookup query to Google DNS (allowed)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "nslookup",
                "example.com",
                "8.8.8.8",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        # Allowlist mode blocks DNS outright. Coi resolves the allowlisted hostnames
        # on the host, writes the addresses into the container's /etc/hosts, and
        # denies every route to a nameserver — so the hosts file is the container's
        # only way to turn a name into an address, and it holds exactly what the
        # firewall holds. Leave the container a resolver and it can learn an address
        # the firewall has never seen, which is the divergence that made allowlist
        # mode flap against rotating cloud frontends in the first place.
        #
        # So a query to 8.8.8.8 must FAIL, even though 8.8.8.8 is in allowed_domains:
        # the address is reachable, port 53 is not.
        assert result.returncode != 0, (
            "DNS to a public resolver must be blocked in allowlist mode — otherwise the container "
            f"can resolve names Coi never saw: {result.stdout}{result.stderr}"
        )

    finally:
        os.unlink(config_file)


def test_allowlist_blocks_non_allowed_dns(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that ALLOWLIST mode blocks DNS servers NOT in allowed_domains.

    Verifies that non-allowlisted DNS servers are blocked.
    """
    # Create temporary config with ALLOWLIST mode (only 8.8.8.8 allowed)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",                 # Google DNS only
]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        # Start container in background with ALLOWLIST mode
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

        # Extract container name from output
        container_name = None
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break

        assert container_name, f"Could not find container name in output: {output}"

        # Wait for firewall rules to be fully applied (poll for default-deny rule)
        assert wait_for_firewall_rules(container_name, timeout=30), (
            "Firewall default-deny rule was not applied in time"
        )

        # Test: nslookup query to Quad9 DNS 9.9.9.9 (NOT in allowlist, should fail)
        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "timeout",
                "5",
                "nslookup",
                "example.com",
                "9.9.9.9",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        # DNS query should fail (blocked)
        assert result.returncode != 0, f"Non-allowed DNS server should be blocked: {result.stderr}"

    finally:
        os.unlink(config_file)
