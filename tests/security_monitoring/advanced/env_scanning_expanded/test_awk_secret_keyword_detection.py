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


def test_awk_secret_keyword_detection(test_workspace, enable_monitoring, coi_binary):
    """Test awk with secret keyword detection (awk/sed now checked alongside grep)."""
    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-53"
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "53",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_container_running(container_name, timeout=30):
            pytest.skip(f"Container {container_name} not found or not running")

        time.sleep(10)

        # Inject awk searching for password
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'awk /password/ .env' sleep 30",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(5)

        state = get_container_state(container_name)
        assert state == "Running", f"Expected Running on WARNING, got {state}"

        events = get_threat_events(container_name)
        warnings = [e for e in events if e.get("level") == "warning"]
        assert len(warnings) > 0, "Expected WARNING for awk password pattern"
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
