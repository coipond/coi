"""End-to-end tests for host-side PROC_EVENTS monitoring via NETLINK_CONNECTOR."""

import subprocess
import time
from pathlib import Path

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_threat_events,
    wait_for_container_running,
)


def test_php_fsockopen_exec_detected(test_workspace, coi_binary):
    """The php-fsockopen exec pattern fires when argv[0] is 'php' and 'fsockopen' is in cmdline.

    Uses exec -a to set argv[0] to the PHP one-liner signature on a sleep process so that
    PROC_EVENT_EXEC fires with the right cmdline without requiring php-cli to be installed.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    # NOTE: auto_kill_on_critical is intentionally DISABLED here. The cmdline
    # contains "fsockopen", which is BOTH the proc_event "php-fsockopen"
    # keyword AND a CRITICAL reverse-shell pattern (process.go). With auto-kill
    # on, the critical reverse-shell detection races the kill against the
    # "high" proc_event this test asserts on, killing the container before the
    # proc_event is observable. This test verifies detection, not killing, so
    # disabling auto-kill makes it deterministic without weakening the assert.
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
process_count_threshold = 9999
process_spawn_rate_threshold = 9999
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-68"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "68",
            "--debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        # Allow monitoring daemon and PROC_EVENTS subscription to initialise.
        time.sleep(3)

        # Use exec -a to set argv[0] to the PHP fsockopen signature and run
        # sleep as the actual process. PROC_EVENT_EXEC fires at execve time,
        # and sleep keeps the process alive long enough to avoid a read race.
        # Re-fire on a cadence: PROC_EVENT_EXEC fires once per execve, and the
        # proc-connector subscription may not be active yet while the daemon is
        # still starting under CI load, so a single exec can be missed. Each
        # launch is a fresh execve; sleep 5 (not 10) avoids piling up re-fires.
        def fire():
            subprocess.Popen(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    "exec -a 'php -r $sock=fsockopen(10.255.255.1,9999)' sleep 5",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        fire()

        # Poll until the proc_event threat appears.
        proc_events = []
        events = []
        for i in range(40):
            events = get_threat_events(container_name)
            proc_events = [
                e
                for e in events
                if e.get("category") == "proc_event"
                and e.get("evidence", {}).get("proc_event", {}).get("pattern") == "php-fsockopen"
            ]
            if proc_events:
                break
            if i % 3 == 2:
                fire()
            time.sleep(1)

        assert len(proc_events) > 0, (
            f"Expected proc_event threat for php fsockopen one-liner, got events: {events}"
        )
        assert proc_events[0].get("level") == "high", (
            f"Expected high level, got: {proc_events[0].get('level')}"
        )
    finally:
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)
