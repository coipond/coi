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


def test_python_socket_exec_detected(test_workspace, coi_binary):
    """Executing a Python reverse-shell one-liner triggers a HIGH proc_event threat."""
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
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
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-67"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "67",
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

        # Run a Python one-liner whose cmdline contains "python3" and
        # "socket.socket", matching the python3-socket exec pattern.
        # Re-fire on a cadence: PROC_EVENT_EXEC fires once per execve, and the
        # proc-connector subscription may not be active yet while the daemon is
        # still starting under CI load, so a single exec can be missed. Each
        # launch is a fresh execve, guaranteeing one fires after subscription.
        def fire():
            subprocess.Popen(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "python3",
                    "-c",
                    "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.close()",
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
                and e.get("evidence", {}).get("proc_event", {}).get("pattern") == "python3-socket"
            ]
            if proc_events:
                break
            if i % 3 == 2:
                fire()
            time.sleep(1)

        assert len(proc_events) > 0, (
            f"Expected proc_event threat for python socket one-liner, got events: {events}"
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
