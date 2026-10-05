"""End-to-end tests for host-side auth.log / syslog monitoring."""

import subprocess
import time
from pathlib import Path

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_threat_events,
    wait_for_container_running,
)


def test_sudo_not_in_sudoers_triggers_high(test_workspace, coi_binary):
    """Writing a 'not in the sudoers file' line triggers a HIGH auth threat."""
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
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
process_count_threshold = 9999
process_spawn_rate_threshold = 9999
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-65"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "65",
            "--debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        # Pre-create an empty auth.log during the settle window so the log
        # watcher registers a DIRECT file watch on it. Otherwise auth.log does
        # not exist at daemon start and first detection depends on catching the
        # file's creation via the parent-directory IN_CREATE watch — a path
        # logwatcher.go documents as unreliable across the overlayfs namespace
        # boundary, which is how this flaked (line present in container, but
        # events: []). With the file already watched, the trigger write below is
        # a plain append/IN_MODIFY on a watched file (the reliable path).
        subprocess.run(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "mkdir -p /var/log && touch /var/log/auth.log",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        time.sleep(5)

        # Write the suspicious line into the container's auth.log.
        def append_sudoers_line():
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    "mkdir -p /var/log && "
                    "echo 'Jun  5 12:00:01 coi sudo: hacker is not in the sudoers file. This incident will be reported.'"
                    " >> /var/log/auth.log",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        append_sudoers_line()

        # Poll until the HIGH auth threat appears. The window is generous for CI
        # load, and the line is re-appended periodically so a monitoring-daemon
        # startup race (the watch not yet active at the first write) can't cause
        # a permanent miss — a fresh line is then picked up by the next poll.
        events = []
        auth_events = []
        for i in range(90):
            events = get_threat_events(container_name)
            auth_events = [
                e for e in events if e.get("category") == "auth" and e.get("level") == "high"
            ]
            if auth_events:
                break
            if i and i % 5 == 0:
                append_sudoers_line()
            time.sleep(1)

        assert len(auth_events) > 0, (
            f"Expected HIGH auth threat for sudoers violation, got events: {events}"
        )
    finally:
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)
