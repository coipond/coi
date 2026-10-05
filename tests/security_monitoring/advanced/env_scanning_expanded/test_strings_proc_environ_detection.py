"""Test detection of expanded environment scanning patterns.

These tests cover new detection patterns added for language-specific
environment access (Python os.environ, Node process.env, Ruby ENV),
expanded grep/awk/sed keywords (credential, auth), and binary tools
reading /proc/*/environ (strings, xxd, hexdump)."""

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


def test_strings_proc_environ_detection(test_workspace, enable_monitoring, coi_binary):
    """Test strings command reading /proc/*/environ detection."""
    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-54"
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "54",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_container_running(container_name):
            pytest.fail(f"Container {container_name} did not start")

        time.sleep(10)

        # Inject strings reading /proc/1/environ
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'strings /proc/1/environ' sleep 30",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(5)

        state = get_container_state(container_name)
        assert state == "Running", f"Expected Running on WARNING, got {state}"

        events = get_threat_events(container_name)
        warnings = [e for e in events if e.get("level") == "warning"]
        assert len(warnings) > 0, "Expected WARNING for strings /proc/*/environ access"
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
