"""Verify that process threats are detected via the host /proc walk.

The monitoring daemon now reads /proc on the host, filtered by the
container's PID namespace, instead of running incus exec ps aux inside
the container.  These tests check that the end-to-end pipeline still
works: process injected into container → host /proc walk finds it →
threat detected → audit log entry written."""

import subprocess
import time

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_reverse_shell_detected_via_host_proc_walk(test_workspace, enable_monitoring, coi_binary):
    """A reverse-shell process in the container must trigger a HIGH or CRITICAL threat.

    The process is injected with exec -a to make its argv[0] look like
    'python -c socket.socket'. The host /proc walk reads cmdline from
    outside the container's mount namespace, so the pattern is visible
    regardless of what /proc looks like inside the container.

    ProcEventWatcher may fire a HIGH threat immediately via PROC_EVENT_EXEC
    before the polling detector has a chance to escalate to CRITICAL.
    """
    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-57"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "57",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_container_running(container_name, timeout=30):
            pytest.skip(f"Container {container_name} not found or not running")

        time.sleep(10)

        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'python -c socket.socket' sleep 30",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        killed = False
        for _ in range(20):
            time.sleep(1)
            if get_container_state(container_name) in ["Stopped", "Frozen", "Unknown"]:
                killed = True
                break

        assert killed, (
            "Container should be paused/killed on reverse-shell detection via host proc walk"
        )

        events = get_threat_events(container_name)
        high_or_critical = [e for e in events if e.get("level") in ("high", "critical")]
        assert len(high_or_critical) > 0, (
            "Expected HIGH or CRITICAL threat event for reverse-shell pattern"
        )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
