"""Verify that a process-count spike triggers a CRITICAL fork-bomb alert.

The monitor reads process counts from the host-side /proc walk, so an
attacker inside the container cannot hide processes by tampering with ps."""

import subprocess
import time
from pathlib import Path

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_threat_events,
    wait_for_container_running,
)


def test_normal_process_count_no_alert(test_workspace, coi_binary):
    """A container running within the process limit must not trigger any
    process-count threat events.
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
process_count_threshold = 100
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-61"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "61",
            "--debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        # Let the monitor run for a few cycles without spawning extra processes
        time.sleep(6)

        events = get_threat_events(container_name)
        count_threats = [e for e in events if "process count" in e.get("title", "").lower()]
        assert len(count_threats) == 0, (
            f"Unexpected process-count threat with high threshold: {count_threats}"
        )
    finally:
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)
