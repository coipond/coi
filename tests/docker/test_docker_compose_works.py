"""
Test for Docker Compose functionality inside Coi containers.

Tests that Docker Compose can start services with port mappings without
sysctl permission errors (e.g., "open sysctl net.ipv4.ip_unprivileged_port_start
file: reopen fd 8: permission denied").

This validates that the security flags (security.nesting, security.syscalls.intercept.mknod,
security.syscalls.intercept.setxattr) are set before the container's first boot, so the
kernel loads the correct seccomp profile.
"""

import subprocess
import time

from support.helpers import (
    calculate_container_name,
)

COMPOSE_YAML = """\
services:
  web:
    image: ghcr.io/mensfeld/nginx:alpine
    ports:
      - "8080:80"
"""


def test_docker_compose_works(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that Docker Compose works inside the container without sysctl errors.

    This specifically tests port mapping which triggers the sysctl
    net.ipv4.ip_unprivileged_port_start check that fails when security
    flags are not set before first boot.

    Flow:
    1. Launch a container
    2. Install Docker if not present
    3. Start Docker daemon
    4. Write a docker-compose.yml with a port-mapped service
    5. Run docker compose up -d
    6. Verify no sysctl errors
    7. Run docker compose down
    8. Cleanup
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

    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "which", "docker"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        install_commands = """
        apt-get update -qq && \
        apt-get install -y -qq ca-certificates curl && \
        install -m 0755 -d /etc/apt/keyrings && \
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && \
        chmod a+r /etc/apt/keyrings/docker.asc && \
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
        apt-get update -qq && \
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
        """

        result = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                install_commands,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, (
            f"Docker installation should succeed. stderr: {result.stderr}"
        )

    # === Phase 3: Start Docker daemon ===

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "systemctl",
            "start",
            "docker",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    time.sleep(5)

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "systemctl",
            "is-active",
            "docker",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"Docker daemon should be active. Output: {result.stdout}, stderr: {result.stderr}"
    )

    # === Phase 4: Write docker-compose.yml ===

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            f"mkdir -p /tmp/compose-test && cat > /tmp/compose-test/docker-compose.yml << 'COMPOSEEOF'\n{COMPOSE_YAML}COMPOSEEOF",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"Writing docker-compose.yml should succeed. stderr: {result.stderr}"
    )

    # === Phase 5: Run docker compose up ===

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "cd /tmp/compose-test && docker compose up -d",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    combined_output = result.stdout + result.stderr

    # The key assertion: no sysctl permission errors
    assert "ip_unprivileged_port_start" not in combined_output.lower(), (
        f"Should not have sysctl ip_unprivileged_port_start errors. output: {combined_output}"
    )
    assert "permission denied" not in combined_output.lower(), (
        f"Should not have permission denied errors. output: {combined_output}"
    )
    assert result.returncode == 0, f"docker compose up should succeed. stderr: {result.stderr}"

    # Wait for service to start
    time.sleep(5)

    # Verify the compose service is running
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "cd /tmp/compose-test && docker compose ps --format json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, f"docker compose ps should succeed. stderr: {result.stderr}"
    # docker compose ps --format json may output to stderr (via coi exec piping)
    ps_output = (result.stdout + result.stderr).lower()
    assert "running" in ps_output, (
        f"Compose service should be running. stdout: {result.stdout}, stderr: {result.stderr}"
    )

    # === Phase 6: Docker compose down ===

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "cd /tmp/compose-test && docker compose down",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, f"docker compose down should succeed. stderr: {result.stderr}"

    # === Phase 7: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
