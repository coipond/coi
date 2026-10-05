"""Test detection of various reverse shell patterns."""

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


def test_perl_reverse_shell_detection(test_workspace, enable_monitoring, coi_binary):
    """Test Perl reverse shell pattern detection."""
    # Capture stderr for debugging
    stderr_file = Path("/tmp") / "coi-test-perl-debug.log"
    stderr_fd = open(stderr_file, "w")  # noqa: SIM115

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "11",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=stderr_fd,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-11"

    if not wait_for_container_running(container_name):
        proc.terminate()
        stderr_fd.close()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Inject Perl reverse shell pattern
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'perl -e use IO::Socket' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(5)

    killed = False
    for _ in range(35):  # a kill (stop + delete) can take ~20s on CI
        time.sleep(1)
        state = get_container_state(container_name)
        if container_absent(container_name):
            killed = True
            break

    # Close stderr and print debug log BEFORE assertions
    proc.terminate()
    stderr_fd.close()

    print("\n=== Coi Perl Test Debug Log ===")
    if stderr_file.exists():
        print(stderr_file.read_text())
    print("=== End Debug Log ===\n")

    assert killed, (
        f"Container should be killed (stopped AND deleted) on Perl reverse shell detection (final observed state: {state!r})"
    )

    # Verify threat logged
    events = get_threat_events(container_name)
    critical = [e for e in events if e.get("level") == "critical"]
    assert len(critical) > 0, "Expected CRITICAL threat for Perl reverse shell"

    cleanup_container(container_name, coi_binary)
