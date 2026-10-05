"""
Test for Docker functionality - verifies Docker actually works inside the container.

Tests that:
1. Launch a container with Docker support
2. Install Docker (if not present)
3. Run a simple Docker container (alpine echo test)
4. Verify Docker container runs successfully without network namespace errors
"""

import subprocess
import time

from support.helpers import (
    calculate_container_name,
)


def test_docker_works_in_container(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that Docker actually works inside the container with nesting enabled.

    Flow:
    1. Launch a container
    2. Install Docker if not present
    3. Start Docker daemon
    4. Run a simple Docker container
    5. Verify success (no network namespace errors)
    6. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container ===

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(5)

    # === Phase 2: Install Docker (if not present) ===

    # Check if Docker is installed
    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "which", "docker"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        # Install Docker using the official convenience script
        install_commands = """
        apt-get update -qq && \
        apt-get install -y -qq ca-certificates curl && \
        install -m 0755 -d /etc/apt/keyrings && \
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && \
        chmod a+r /etc/apt/keyrings/docker.asc && \
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
        apt-get update -qq && \
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io
        """

        result = subprocess.run(
            [coi_binary, "container", "exec", container_name, "--", "bash", "-c", install_commands],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, (
            f"Docker installation should succeed. stderr: {result.stderr}"
        )

    # === Phase 3: Start Docker daemon ===

    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "systemctl", "start", "docker"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Wait for Docker daemon to be ready
    time.sleep(5)

    # Verify Docker daemon is running
    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "systemctl", "is-active", "docker"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"Docker daemon should be active. Output: {result.stdout}, stderr: {result.stderr}"
    )

    # === Phase 4: Run a simple Docker container ===

    # Pull alpine image and run a simple command
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "docker",
            "run",
            "--rm",
            "ghcr.io/coipond/alpine:latest",
            "echo",
            "Docker works!",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, (
        f"Docker container should run successfully. stderr: {result.stderr}"
    )
    # Docker output goes to stderr when pulling images, check both stdout and stderr
    output = result.stdout + result.stderr
    assert "Docker works!" in output, (
        f"Docker container should produce expected output. output: {output}"
    )

    # Verify no network namespace errors
    assert "network namespace" not in result.stderr.lower(), (
        f"Should not have network namespace errors. stderr: {result.stderr}"
    )
    assert "ip_unprivileged_port_start" not in result.stderr.lower(), (
        f"Should not have sysctl errors. stderr: {result.stderr}"
    )

    # === Phase 5: Verify docker works without sudo as the code user ===
    #
    # The code user (UID 1000, GID 1000) must be able to run docker without sudo.
    # This replicates the real-world call: incus exec --user 1000 --group 1000
    # which sets UID/GID but does NOT load supplementary groups (including 'docker').
    # Docker daemon is configured to use the 'code' group (GID 1000) as the socket
    # owner, so the primary group GID 1000 gives access even without supplementary
    # groups being loaded.

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--user",
            "1000",
            "--group",
            "1000",
            "--",
            "docker",
            "run",
            "--rm",
            "ghcr.io/coipond/alpine:latest",
            "echo",
            "Docker without sudo works!",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, (
        f"docker should work without sudo as code user (UID 1000, GID 1000). "
        f"Check /etc/docker/daemon.json 'group' setting. stderr: {result.stderr}"
    )
    output = result.stdout + result.stderr
    assert "Docker without sudo works!" in output, (
        f"Docker as code user should produce expected output. output: {output}"
    )

    # === Phase 6: Test Docker with network isolation (default behavior) ===

    # Run another container to verify network namespaces work properly
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "docker",
            "run",
            "--rm",
            "ghcr.io/coipond/alpine:latest",
            "sh",
            "-c",
            "ip addr show",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (
        f"Docker container with network should work. stderr: {result.stderr}"
    )
    # Docker output may go to stderr, check both
    output = result.stdout + result.stderr
    assert "eth0" in output or "lo" in output, (
        f"Docker container should have network interfaces. output: {output}"
    )

    # === Phase 7: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
