"""
Test for Docker without nesting flags - demonstrates the fix necessity.

Tests that:
1. Launch a container
2. Manually disable the Docker support flags
3. Try to run Docker
4. Verify it FAILS with the specific network namespace error

This is a regression test proving our automatic Docker support fix works.
"""

import subprocess
import time

from support.helpers import calculate_container_name


def test_docker_fails_without_nesting(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that Docker fails without nesting flags (regression test).

    Flow:
    1. Launch a container (has Docker flags by default)
    2. Manually unset the Docker support flags
    3. Restart container to apply changes
    4. Install Docker if not present
    5. Try to run a simple Docker container
    6. Verify it FAILS with network namespace error
    7. Cleanup
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

    time.sleep(3)

    # === Phase 2: Manually disable Docker support flags ===

    # Unset security.nesting
    result = subprocess.run(
        [
            "incus",
            "--project",
            "default",
            "config",
            "unset",
            container_name,
            "security.nesting",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, f"Failed to unset security.nesting. stderr: {result.stderr}"

    # Unset security.syscalls.intercept.mknod
    result = subprocess.run(
        [
            "incus",
            "--project",
            "default",
            "config",
            "unset",
            container_name,
            "security.syscalls.intercept.mknod",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"Failed to unset security.syscalls.intercept.mknod. stderr: {result.stderr}"
    )

    # Unset security.syscalls.intercept.setxattr
    result = subprocess.run(
        [
            "incus",
            "--project",
            "default",
            "config",
            "unset",
            container_name,
            "security.syscalls.intercept.setxattr",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"Failed to unset security.syscalls.intercept.setxattr. stderr: {result.stderr}"
    )

    # === Phase 3: Restart container to apply changes ===

    result = subprocess.run(
        ["incus", "--project", "default", "restart", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, f"Container restart should succeed. stderr: {result.stderr}"

    time.sleep(5)

    # === Phase 4: Install Docker (if not present) ===

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

    # Start Docker daemon
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

    # Wait for Docker daemon to be ready
    time.sleep(5)

    # Verify Docker daemon is running
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

    # === Phase 5: Try to run Docker container (should FAIL) ===

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
            "Should not work!",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    # === Phase 6: Verify it FAILS with the expected error ===

    # Docker should fail without nesting support
    assert result.returncode != 0, (
        "Docker container should FAIL without nesting flags. "
        f"stdout: {result.stdout}, stderr: {result.stderr}"
    )

    # Check for the specific error we're fixing
    output = result.stdout + result.stderr
    error_indicators = [
        "ip_unprivileged_port_start",  # The specific sysctl error
        "permission denied",  # Permission error
        "failed to create",  # Container creation failure
    ]

    has_expected_error = any(indicator in output.lower() for indicator in error_indicators)
    assert has_expected_error, f"Should have Docker nesting error. Output: {output}"

    # === Phase 7: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
