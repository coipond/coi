"""Test detection of multiple simultaneous threats."""

import subprocess
import time

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_threat_events,
    wait_for_container_running,
)


def test_rapid_threat_burst(test_workspace, enable_monitoring, coi_binary):
    """Test that rapid successive threats are all detected and logged."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "45",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-45"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline
    time.sleep(5)

    # Fire multiple WARNING-level threats using the exec -a pattern
    # This replaces the process name (argv[0]) so it appears as 'env' in ps/proc
    # while actually running sleep for long enough to be detected
    for _ in range(3):
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                # exec -a replaces argv[0] so the process appears as 'env' to monitoring
                "exec -a 'env' sleep 10",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

    # Wait for monitoring to process
    time.sleep(15)

    # Check that threats were logged
    events = get_threat_events(container_name)
    env_warnings = [
        e for e in events if e.get("level") == "warning" and e.get("category") == "environment"
    ]

    proc.terminate()

    print("\n=== Rapid Threat Burst Test Debug ===")
    print(f"Total events: {len(events)}")
    print(f"Env warning events: {len(env_warnings)}")
    for e in events:
        print(f"  - {e.get('level')} / {e.get('category')} / {e.get('title')}")
    print("=== End Debug ===\n")

    # Should detect at least some of the rapid threats
    # (deduplication may combine some within 30s window)
    assert len(env_warnings) >= 1, (
        f"Expected at least 1 env scanning warning from rapid burst, got {len(env_warnings)}"
    )

    cleanup_container(container_name, coi_binary)
