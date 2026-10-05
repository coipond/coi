"""Verify that a sudden burst of new processes triggers a CRITICAL spawn-rate alert.

Unlike the absolute-count check (TestForkBombDetection), spawn-rate detection
fires when the process delta between two consecutive polls exceeds the configured
threshold — even if the total process count is still below the absolute limit."""

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


def test_spawn_rate_spike_kills_container(test_workspace, coi_binary):
    """Spawning many processes in a single burst must trigger a CRITICAL
    'Process spawn rate spike detected' event and (with auto_kill_on_critical)
    kill the container.

    The absolute process_count_threshold is set very high (9999) so only
    the spawn-rate check fires.
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
process_spawn_rate_threshold = 10
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-62"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "62",
            "--debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        # Give monitoring a few seconds to establish a baseline process count.
        time.sleep(5)

        # Spawn bursts of long-lived sleep processes. A burst of ~20 far
        # exceeds the spawn-rate threshold of 10 within one 1-second poll.
        # We spawn several bursts over time rather than one: a single burst can
        # be missed if it coincides with a process-collection gap (which resets
        # the detector's baseline to "first poll") — repeated bursts make
        # detection robust, and the longer window absorbs kill latency on
        # loaded CI runners.
        def spawn_burst():
            subprocess.Popen(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    "for i in $(seq 1 20); do sleep 120 & done",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        killed = False
        for i in range(40):
            if i % 4 == 0:
                spawn_burst()
            time.sleep(1)
            if container_absent(container_name):
                killed = True
                break

        assert killed, (
            "Container should be killed (stopped AND deleted) when spawn rate "
            f"exceeds threshold, but it still exists as {get_container_state(container_name)!r}"
        )

        events = get_threat_events(container_name)
        rate_events = [
            e
            for e in events
            if e.get("level") == "critical" and "spawn rate" in e.get("title", "").lower()
        ]
        assert len(rate_events) > 0, "Expected CRITICAL spawn-rate threat event"

        evidence = rate_events[0].get("evidence", {}).get("process_count", {})
        assert evidence.get("delta", 0) > 10, "Evidence should record process delta > threshold"
        assert evidence.get("threshold") == 10, "Evidence should record configured threshold"
    finally:
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)
