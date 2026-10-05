"""Verify that a process-count spike triggers a CRITICAL fork-bomb alert.

The monitor reads process counts from the host-side /proc walk, so an
attacker inside the container cannot hide processes by tampering with ps."""

import subprocess
import time
from pathlib import Path

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_fork_bomb_kills_container(test_workspace, coi_binary):
    """Spawning many processes inside the container must trigger a CRITICAL
    threat and (with auto_kill_on_critical) kill the container.

    Uses a low process_count_threshold (15) so a simple shell loop is
    enough to trip the detector without needing a real fork bomb.
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
process_count_threshold = 15
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-60"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "60",
            "--debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        # Give monitoring a couple of seconds to establish baseline
        time.sleep(3)

        # Spawn many long-lived sleep processes to exceed the threshold.
        # Using a bounded loop rather than a real fork bomb avoids
        # destabilising the CI runner.
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "for i in $(seq 1 30); do sleep 60 & done",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        killed = False
        for _ in range(20):
            time.sleep(1)
            if container_absent(container_name):
                killed = True
                break

        assert killed, (
            "Container should be killed (stopped AND deleted) when process count "
            f"exceeds threshold, but it still exists as {get_container_state(container_name)!r}"
        )

        events = get_threat_events(container_name)
        critical = [
            e
            for e in events
            if e.get("level") == "critical" and "process count" in e.get("title", "").lower()
        ]
        assert len(critical) > 0, "Expected CRITICAL process-count threat event"

        evidence = critical[0].get("evidence", {}).get("process_count", {})
        assert evidence.get("count", 0) > 15, "Evidence should record observed process count"
        assert evidence.get("threshold") == 15, "Evidence should record configured threshold"
    finally:
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)
