"""
Integration tests for network OPEN mode.

Tests that OPEN mode allows unrestricted network access to all destinations,
including public internet, RFC1918 private networks, and metadata endpoints (with block_metadata_endpoint = false).

Network isolation is implemented using nft rules in restricted/allowlist modes.
OPEN mode has no firewall rules applied.
"""

import os
import subprocess
import tempfile


def test_open_allows_public_internet(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that OPEN mode allows access to public internet.

    Verifies that containers can reach public websites and HTTPS endpoints.
    """
    # Create temporary config with OPEN mode
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "open"
""")
        config_file = f.name

    try:
        # Start container in background with OPEN mode
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

        # Test: curl example.com (HTTP)
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
                "10",
                "http://example.com",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        assert result.returncode == 0, f"Failed to reach example.com: {result.stderr}"
        assert "Example Domain" in result.stderr, (
            f"Unexpected response from example.com: {result.stderr}"
        )

        # Test: curl registry.npmjs.org (HTTPS)
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

        assert result.returncode == 0, f"Failed to reach registry.npmjs.org: {result.stderr}"
        assert "HTTP" in result.stderr, f"No HTTP response from registry.npmjs.org: {result.stderr}"

    finally:
        os.unlink(config_file)


def test_open_allows_rfc1918(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that OPEN mode allows access to RFC1918 private networks.

    Verifies that containers can attempt connections to private IP addresses
    without ACL blocking (connections may timeout if no service exists).
    """
    # Create temporary config with OPEN mode
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "open"
""")
        config_file = f.name

    try:
        # Start container in background with OPEN mode
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

        # Test: attempt connection to 10.0.0.1 (Class A private network)
        # Connection will timeout, but should NOT be rejected by ACL
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
                "3",
                "http://10.0.0.1",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # Connection will fail (timeout), but NOT due to ACL rejection
        # In OPEN mode, we expect timeout errors, not "connection refused" from ACL
        output_text = result.stderr.lower()
        # Should NOT see immediate rejection (which would indicate ACL blocking)
        assert "connection refused" not in output_text or "timed out" in output_text, (
            f"RFC1918 address appears to be blocked by ACL in OPEN mode: {result.stderr}"
        )

    finally:
        os.unlink(config_file)


def test_open_allows_metadata_endpoint(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that OPEN mode with block_metadata_endpoint = false allows access to
    the cloud metadata endpoint (169.254.169.254).

    Verifies that containers can attempt connections to the metadata endpoint
    without ACL blocking.

    Note: In cloud environments (Azure CI), a real metadata service exists.
    This test verifies ACL behavior, not the presence/absence of the service.
    """
    # Create temporary config with OPEN mode
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "open"
block_metadata_endpoint = false
""")
        config_file = f.name

    try:
        # Start container in background with OPEN mode
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

        # Test: attempt connection to metadata endpoint
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
                "3",
                "http://169.254.169.254",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        output_text = result.stderr.lower()

        # In OPEN mode, either outcome is acceptable:
        # - Success (returncode == 0): Cloud environment with real metadata service
        # - Timeout/failure: Local environment with no metadata service
        # Both are valid - we just verify it's not being blocked by ACL with immediate rejection
        if result.returncode == 0:
            # Metadata service exists and is reachable (cloud environment) - this is OK in OPEN mode
            pass
        else:
            # Connection failed (local environment) - should be timeout, not ACL rejection
            assert "connection refused" not in output_text or "timed out" in output_text, (
                f"Metadata endpoint appears to be blocked by ACL in OPEN mode: {result.stderr}"
            )

    finally:
        os.unlink(config_file)


def test_open_dns_resolution(coi_binary, workspace_dir, cleanup_containers):
    """
    Test that DNS resolution works in OPEN mode.

    Verifies that containers can perform DNS queries to public DNS servers.
    """
    # Create temporary config with OPEN mode
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "open"
""")
        config_file = f.name

    try:
        # Start container in background with OPEN mode
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

        # Test: nslookup query to Google DNS
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

        assert result.returncode == 0, f"DNS query failed: {result.stderr}"
        # Should return an IP address in the output
        output_text = result.stderr
        assert "Address" in output_text or "address" in output_text.lower(), (
            f"No DNS response received: {result.stderr}"
        )

    finally:
        os.unlink(config_file)
