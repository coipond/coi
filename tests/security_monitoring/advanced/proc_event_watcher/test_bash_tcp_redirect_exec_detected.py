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


def test_bash_tcp_redirect_exec_detected(test_workspace, coi_binary):
    """Executing 'bash -c /dev/tcp/...' inside a container triggers a HIGH proc_event threat.

    The bash-tcp-redirect pattern matches when bash itself (argv[0]) opens a
    /dev/tcp/ redirect — a canonical reverse-shell one-liner technique.
    bash -i alone is intentionally NOT detected to avoid false positives from
    legitimate interactive shells started by the host tooling.
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
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-66"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "66",
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

        # Run bash with a /dev/tcp/ redirect — the canonical bash reverse-shell
        # pattern. PROC_EVENT_EXEC fires on execve before the shell tries to
        # connect, so we don't wait for the command to complete (the TCP
        # connection attempt may hang if no RST is returned by the network).
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
                    "bash",
                    "-c",
                    "bash -c 'exec 3>/dev/tcp/10.255.255.1/9999' 2>/dev/null; true",
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
                and e.get("evidence", {}).get("proc_event", {}).get("pattern")
                == "bash-tcp-redirect"
            ]
            if proc_events:
                break
            if i % 3 == 2:
                fire()
            time.sleep(1)

        assert len(proc_events) > 0, (
            f"Expected proc_event threat for bash /dev/tcp redirect, got events: {events}"
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
