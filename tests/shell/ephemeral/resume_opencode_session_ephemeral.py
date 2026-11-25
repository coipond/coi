"""
Test for coi shell - ephemeral opencode session with resume.

Tests that sessions saved with [tool] name = "opencode" can be resumed.
The opencode tool stores its config under .config/opencode (not .claude),
so this verifies that session detection is tool-agnostic.

Flow:
1. Write .coi/config.toml with [tool] name = "opencode"
2. Start dummy in ephemeral mode
3. Send a message and verify response
4. Exit to bash shell
5. Issue sudo poweroff
6. Verify container is removed and session saved
7. Run coi shell --resume
8. Verify session was resumed (check for "Auto-detected session" in output)
9. Cleanup
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


def test_ephemeral_opencode_session_with_resume(coi_binary, cleanup_containers, workspace_dir):
    """
    Test ephemeral opencode session resume after shutdown.

    This is the opencode variant of new_session_with_resume_ephemeral.py.
    It verifies that --resume works when the tool is opencode, whose config
    lives under .config/opencode instead of .claude.
    """
    import os

    # Write .coi/config.toml to select opencode as the tool
    config_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config.toml")
    with open(config_path, "w") as f:
        f.write('[tool]\nname = "opencode"\n')

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

    # Wait for container deletion
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

    # Also check for "Auto-detected session" in raw output
    if hasattr(child2.logfile_read, "get_raw_output"):
        output2 = child2.logfile_read.get_raw_output()
    elif hasattr(child2.logfile_read, "get_display_stripped"):
        output2 = child2.logfile_read.get_display_stripped()
    else:
        output2 = ""

    auto_detected = "Auto-detected session" in output2

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

    # Wait for second container to be deleted
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
    assert resumed or auto_detected, (
        f"Should see 'Resuming session' or 'Auto-detected session' in output. Got:\n{output2}"
    )
