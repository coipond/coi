"""
Test for coi shell in persistent mode - opencode session with resume.

Tests that persistent sessions saved with [tool] name = "opencode" can be resumed.
The opencode tool stores its config under .config/opencode (not .claude),
so this verifies that session detection is tool-agnostic.

Flow:
1. Write .coi/config.toml with [tool] name = "opencode" and [container] persistent = true
2. Start dummy in persistent mode
3. Send a message and verify response
4. Exit to bash shell
5. Issue sudo poweroff (container kept in persistent mode)
6. Delete container to simulate fresh start
7. Run coi shell --resume
8. Verify session was resumed (dummy shows "Resuming session")
9. Cleanup
"""

import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    get_container_list,
    send_prompt,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    wait_for_text_on_screen,
    with_live_screen,
)


def test_persistent_opencode_session_with_resume(coi_binary, cleanup_containers, workspace_dir):
    """
    Test persistent opencode session resume.

    This is the opencode variant of session_with_resume.py.
    It verifies that resuming a persistent session works when the tool is opencode.
    """
    import os

    # Write .coi/config.toml to select opencode as the tool and enable
    # persistent mode (persistence is config-driven: [container] persistent).
    config_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config.toml")
    with open(config_path, "w") as f:
        f.write('[tool]\nname = "opencode"\n\n[container]\npersistent = true\n')

    env = {"COI_USE_DUMMY": "1"}

    # === Phase 1: Initial persistent session ===

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
    if hasattr(child.logfile_read, "get_raw_output"):
        output1 = child.logfile_read.get_raw_output()
    elif hasattr(child.logfile_read, "get_output"):
        output1 = child.logfile_read.get_output()
    else:
        output1 = ""

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    # Give time for cleanup
    time.sleep(3)

    # Verify session was saved
    assert "Session data saved" in output1 or "Saving session data" in output1, (
        f"Session should be saved. Got:\n{output1}"
    )

    # In persistent mode, container is kept - delete it for clean resume test
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
    time.sleep(1)

    # === Phase 2: Resume persistent session ===

    child2 = spawn_coi(
        coi_binary,
        ["shell", "--resume"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child2, timeout=60)

    # Wait for dummy to show resume message
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

    # For opencode the "Resuming session" line comes from coi's own setup log
    # ("[setup] Resuming session - using restored opencode config"), printed
    # before the tmux attach takes over the screen. A faster setup can clear it
    # from the screen before the poll above sees it, so also accept it in the
    # full captured output — the same evidence, without the race.
    if not resumed and "Resuming session" in output2:
        resumed = True

    # Cleanup: exit and delete container
    child2.send("exit")
    time.sleep(0.3)
    child2.send("\x0d")
    time.sleep(2)

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

    # Give time for cleanup
    time.sleep(3)

    # Force delete container
    container_name2 = calculate_container_name(workspace_dir, 1)
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
