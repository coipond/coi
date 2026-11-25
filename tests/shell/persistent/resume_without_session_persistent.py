"""
Test for coi shell --resume in persistent mode (config-driven) when no saved session exists.

Tests that:
1. Running --resume in persistent mode with no saved session errors gracefully
2. Error message is helpful and suggests what to do
3. No container is created/left behind
"""

import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    child_output,
    get_container_list,
    spawn_coi,
    with_live_screen,
    write_workspace_container_config,
)


def test_persistent_resume_without_session(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that --resume in persistent mode with no saved session errors gracefully.

    Flow:
    1. Run coi shell --resume in fresh persistent workspace (no saved sessions)
    2. Verify it exits with error
    3. Verify error message is helpful
    4. Verify no containers were created
    """
    env = {"COI_USE_DUMMY": "1"}

    # Persistence is config-driven: [container] persistent = true
    write_workspace_container_config(workspace_dir, persistent=True)

    # Get container list before
    containers_before = get_container_list()

    # Launch with --resume in persistent mode - should fail since no session exists
    child = spawn_coi(
        coi_binary,
        ["shell", "--resume"],
        cwd=workspace_dir,
        env=env,
        timeout=30,
    )

    # Use live screen to capture output
    with with_live_screen(child):
        # Wait for process to exit (should be quick since it errors)
        try:
            child.expect(EOF, timeout=30)
        except TIMEOUT:
            pass

        time.sleep(1)

    # Get output for verification
    output = child_output(child)

    # Close the child process
    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    # Should exit with non-zero status
    assert child.exitstatus != 0, (
        f"Expected non-zero exit code, got {child.exitstatus}. Output:\n{output}"
    )

    # Error message should be helpful - workspace-scoped error
    output_lower = output.lower()

    assert "no previous session to resume" in output_lower or "no saved sessions" in output_lower, (
        f"Error should mention 'no previous session to resume'. Got:\n{output}"
    )

    # Verify no new containers were created
    containers_after = get_container_list()
    new_containers = set(containers_after) - set(containers_before)

    assert len(new_containers) == 0, (
        f"No containers should be created on resume error. New containers: {new_containers}"
    )
