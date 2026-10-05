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


def test_failed_ssh_login_detected(test_workspace, coi_binary):
    """Writing a 'Failed password' line to auth.log triggers a WARNING auth threat."""
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
process_spawn_rate_threshold = 9999
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-64"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "64",
            "--debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        # Allow monitoring daemon to start.
        time.sleep(3)

        def inject_ssh_failure():
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    "mkdir -p /var/log && "
                    "echo 'Jun  5 12:00:00 coi sshd[1234]: Failed password for invalid user attacker from 1.2.3.4 port 22222 ssh2'"
                    " >> /var/log/auth.log",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        # Write the suspicious line into the container's auth.log,
        # re-injecting on EVERY poll iteration: a single write (or sparse
        # re-injections) can land before the watcher has registered its
        # inotify watch under CI load and be missed entirely — re-writing
        # each iteration guarantees a write lands after registration.
        # (Same de-flake pattern as test_log_watcher_inotify.py.)
        auth_events = []
        for _ in range(60):
            inject_ssh_failure()
            time.sleep(1)
            events = get_threat_events(container_name)
            auth_events = [
                e
                for e in events
                if e.get("category") == "auth"
                and e.get("evidence", {}).get("auth_log", {}).get("pattern")
                == "ssh_failed_password"
            ]
            if auth_events:
                break

        assert len(auth_events) > 0, (
            f"Expected auth threat for failed SSH login, got events: {events}"
        )
        assert auth_events[0].get("level") == "warning", (
            f"Expected warning level, got: {auth_events[0].get('level')}"
        )
    finally:
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)
