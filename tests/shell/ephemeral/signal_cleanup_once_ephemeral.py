"""
Test that signal-triggered cleanup runs exactly once.

Verifies that:
1. Sending SIGTERM to the coi process triggers cleanup
2. The "Cleaning up session..." message appears exactly once

This guards against a race condition where both the defer and signal handler
could call doCleanup() concurrently without sync.Once protection.
"""

import os
import signal
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    child_output,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
)


def test_signal_cleanup_runs_once(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that SIGTERM triggers cleanup exactly once.

    Flow:
    1. Start coi shell in ephemeral mode with dummy tool
    2. Wait for session to be fully ready
    3. Send SIGTERM directly to the coi process to trigger signal handler
    4. Verify "Cleaning up session..." appears exactly once in output
    """
    env = {"COI_USE_DUMMY": "1"}

    child = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    # Send SIGTERM directly to the coi process to trigger signal handler cleanup
    os.kill(child.pid, signal.SIGTERM)

    # Wait for process to exit — cleanup may take a while on CI
    try:
        child.expect(EOF, timeout=120)
    except TIMEOUT:
        pass

    # Give time for cleanup messages to be captured
    time.sleep(2)

    # Capture output before closing
    output = child_output(child)

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    # Verify cleanup message appears exactly once — this is the core assertion
    # that validates sync.Once prevents double-execution from both the defer
    # and signal handler paths
    cleanup_count = output.count("Cleaning up session...")
    assert cleanup_count == 1, (
        f"'Cleaning up session...' should appear exactly once, "
        f"but appeared {cleanup_count} times. Output:\n{output}"
    )
