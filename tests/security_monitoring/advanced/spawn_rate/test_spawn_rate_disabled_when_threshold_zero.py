"""Verify that a sudden burst of new processes triggers a CRITICAL spawn-rate alert.

Unlike the absolute-count check (TestForkBombDetection), spawn-rate detection
fires when the process delta between two consecutive polls exceeds the configured
threshold — even if the total process count is still below the absolute limit."""

import subprocess
import time
from pathlib import Path

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_threat_events,
    wait_for_container_running,
)


def test_spawn_rate_disabled_when_threshold_zero(test_workspace, coi_binary):
    """With process_spawn_rate_threshold = 0 (disabled), a burst of new processes
    must not trigger any spawn-rate threat events.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
process_count_threshold = 9999
process_spawn_rate_threshold = 0
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-63"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "63",
            "--debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        time.sleep(3)

        # Spawn 25 processes — with threshold=0 this should not trigger any alert
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "for i in $(seq 1 25); do sleep 60 & done",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(6)

        events = get_threat_events(container_name)
        rate_events = [e for e in events if "spawn rate" in e.get("title", "").lower()]
        assert len(rate_events) == 0, (
            f"Unexpected spawn-rate threat with threshold=0: {rate_events}"
        )
    finally:
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)
