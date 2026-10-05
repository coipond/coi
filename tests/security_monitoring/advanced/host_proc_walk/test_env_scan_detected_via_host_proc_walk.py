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
    get_threat_events,
    wait_for_container_running,
)


def test_env_scan_detected_via_host_proc_walk(test_workspace, enable_monitoring, coi_binary):
    """An env-scanning process in the container must trigger a WARNING.

    Uses exec -a to rename the process argv[0] to 'env', which matches
    the env-scan pattern in checkEnvAccess. The host /proc walk reads
    /proc/<pid>/cmdline, which contains the full argv including the
    renamed arg, so the pattern is still visible from outside the
    container.
    """
    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-56"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "56",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_container_running(container_name):
            pytest.fail(f"Container {container_name} did not start")

        time.sleep(10)

        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'env' sleep 30",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        warning_found = False
        for _ in range(20):
            time.sleep(1)
            events = get_threat_events(container_name)
            if any(e.get("level") == "warning" for e in events):
                warning_found = True
                break

        assert warning_found, "Expected WARNING for env-scan command via host proc walk"
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
