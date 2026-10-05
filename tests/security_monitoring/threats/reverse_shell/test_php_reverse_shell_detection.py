"""Test detection of various reverse shell patterns."""

import subprocess
import time

import pytest

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_php_reverse_shell_detection(test_workspace, enable_monitoring, coi_binary):
    """Test PHP reverse shell pattern detection."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "12",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-12"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Inject PHP reverse shell pattern
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'php -r fsockopen' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(5)

    killed = False
    for _ in range(15):
        time.sleep(1)
        state = get_container_state(container_name)
        if container_absent(container_name):
            killed = True
            break

    # DEBUG: Print state and events if not killed
    if not killed:
        events = get_threat_events(container_name)
        print("\n=== DEBUG: PHP test - container not killed ===")
        print(f"Final state: {get_container_state(container_name)}")
        print(f"Total threat events: {len(events)}")
        for event in events:
            print(
                f"- level={event.get('level')}, category={event.get('category')}, "
                f"title={event.get('title')}, desc={event.get('description')[:100] if event.get('description') else 'N/A'}"
            )
        print("=== END DEBUG ===\n")

    assert killed, (
        f"Container should be killed (stopped AND deleted) on PHP reverse shell detection (final observed state: {state!r})"
    )

    # Verify threat logged
    events = get_threat_events(container_name)
    critical = [e for e in events if e.get("level") == "critical"]

    if len(critical) == 0:
        print("\n=== DEBUG: No CRITICAL events found ===")
        print(f"All events: {events}")
        print("=== END DEBUG ===\n")

    assert len(critical) > 0, "Expected CRITICAL threat for PHP reverse shell"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
