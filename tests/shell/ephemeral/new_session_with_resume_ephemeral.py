"""
Test for coi shell - ephemeral session with resume.

Tests the resume lifecycle:
1. Start dummy in ephemeral mode
2. Send a message and verify response
3. Exit to bash shell
4. Issue sudo poweroff
5. Verify container is removed
6. Run coi shell --resume
7. Verify session was resumed (dummy shows "Resuming session")
8. Cleanup
"""

import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    child_output,
    get_container_list,
    send_prompt,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_specific_container_deletion,
    wait_for_text_in_monitor,
    wait_for_text_on_screen,
    with_live_screen,
)


def test_ephemeral_session_with_resume(coi_binary, cleanup_containers, workspace_dir):
    """
    Test ephemeral session resume after shutdown.

    Flow:
    1. Start coi shell (ephemeral mode)
    2. Interact with dummy
    3. Exit claude to bash, then poweroff
    4. Verify container deleted
    5. Run coi shell --resume
    6. Verify resume worked
    7. Cleanup
    """
    env = {"COI_USE_DUMMY": "1"}

    # === Phase 1: Initial session ===

    child = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    container_name = calculate_container_name(workspace_dir, 1)

    # Interact with dummy
    with with_live_screen(child) as monitor:
        time.sleep(2)
        send_prompt(child, "remember this message")
        responded = wait_for_text_in_monitor(monitor, "remember this message-BACK", timeout=30)
        assert responded, "Dummy CLI should respond"

    # Exit CLI to bash
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(2)

    # Wait for bash prompt to be ready
    time.sleep(3)

    # Verify we're in bash
    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send("echo $((11111+22222))")
        time.sleep(0.5)
        child.send("\x0d")
        time.sleep(2)
        # 11111 + 22222 = 33333
        in_bash = wait_for_text_in_monitor(monitor, "33333", timeout=20)
        assert in_bash, "Should be in bash shell"

    # Poweroff container
    child.send("sudo poweroff")
    time.sleep(0.3)
    child.send("\x0d")

    # Wait for process to exit
    try:
        child.expect(EOF, timeout=60)
    except TIMEOUT:
        pass

    # Get output
    output1 = child_output(child)

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    # Wait for container deletion (60s to account for cleanup detection + network teardown)
    # The wait function polls, so no need for a sleep before waiting
    container_deleted = wait_for_specific_container_deletion(container_name, timeout=60)
    assert container_deleted, (
        f"Container {container_name} should be deleted after poweroff (waited 60s)"
    )

    # Verify session was saved
    assert "Session data saved" in output1 or "Saving session data" in output1, (
        f"Session should be saved. Got:\n{output1}"
    )

    # === Phase 2: Resume session ===

    child2 = spawn_coi(
        coi_binary,
        ["shell", "--resume"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child2, timeout=60)

    # Wait for dummy to show resume message
    # Fake-claude prints "Resuming session: <session-id>" when resuming
    try:
        wait_for_text_on_screen(child2, "Resuming session", timeout=30)
        resumed = True
    except TimeoutError:
        resumed = False

    # Get output for debugging
    if hasattr(child2.logfile_read, "get_raw_output"):
        output2 = child2.logfile_read.get_raw_output()
    elif hasattr(child2.logfile_read, "get_display_stripped"):
        output2 = child2.logfile_read.get_display_stripped()
    else:
        output2 = ""

    # Cleanup: exit and kill container
    child2.send("exit")
    time.sleep(0.3)
    child2.send("\x0d")
    time.sleep(2)

    # Poweroff to trigger cleanup
    child2.send("sudo poweroff")
    time.sleep(0.3)
    child2.send("\x0d")

    try:
        child2.expect(EOF, timeout=60)
    except TIMEOUT:
        pass

    try:
        child2.close(force=False)
    except Exception:
        child2.close(force=True)

    # Wait for second container to be deleted (60s to account for cleanup detection + network teardown)
    container_name2 = calculate_container_name(workspace_dir, 1)
    deleted = wait_for_specific_container_deletion(container_name2, timeout=60)

    # Force cleanup if container still exists
    if not deleted:
        subprocess.run(
            [coi_binary, "container", "delete", container_name2, "--force"],
            capture_output=True,
            timeout=30,
        )

    # Verify container is gone
    time.sleep(1)
    containers = get_container_list()
    assert container_name2 not in containers, (
        f"Container {container_name2} should be deleted after cleanup"
    )

    # Assert resume worked
    assert resumed, f"Should see 'Resuming session' in output. Got:\n{output2}"
