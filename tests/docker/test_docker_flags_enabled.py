"""
Test for Docker support flags - verifies nesting flags are automatically enabled.

Tests that:
1. Launch a container
2. Verify security.nesting is set to true
3. Verify security.syscalls.intercept.mknod is set to true
4. Verify security.syscalls.intercept.setxattr is set to true
5. Verify linux.sysctl.net.ipv4.ip_unprivileged_port_start is set to 0
"""

import subprocess
import time

from support.helpers import (
    calculate_container_name,
    container_config_get,
)


def test_docker_flags_enabled(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that Docker support flags are automatically enabled on container launch.

    Flow:
    1. Launch a container
    2. Verify all four Docker-related settings are enabled
    3. Cleanup
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

    # === Phase 2: Verify Docker support flags are enabled ===

    # Check security.nesting
    assert container_config_get(container_name, "security.nesting") == "true", (
        "security.nesting should be enabled for Docker support"
    )

    # Check security.syscalls.intercept.mknod
    assert container_config_get(container_name, "security.syscalls.intercept.mknod") == "true", (
        "security.syscalls.intercept.mknod should be enabled for Docker support"
    )

    # Check security.syscalls.intercept.setxattr
    assert container_config_get(container_name, "security.syscalls.intercept.setxattr") == "true", (
        "security.syscalls.intercept.setxattr should be enabled for Docker support"
    )

    # Check linux.sysctl.net.ipv4.ip_unprivileged_port_start
    assert (
        container_config_get(container_name, "linux.sysctl.net.ipv4.ip_unprivileged_port_start")
        == "0"
    ), "linux.sysctl.net.ipv4.ip_unprivileged_port_start should be 0 for Docker support"

    # === Phase 3: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
