"""
Test for coi shell --resume in persistent mode - verifies the stopped container is reused.

When a persistent session is resumed, coi should restart the original stopped container
on the same slot rather than creating a fresh container on a new slot. This ensures that
system-level changes (installed packages, files outside ~/.claude) persist across resume.

Bug: AllocateSlot() only checks running containers, so a stopped persistent container's
slot appears "available" and a new slot is allocated, creating a fresh container.

Flow:
1. Start persistent session on slot 1
2. Exit to bash, create a marker file at /var/tmp/persist-marker-Coi-TEST
3. Poweroff (container stops but is kept)
4. Verify stopped container still exists
5. Resume with --resume (no explicit --slot)
6. Check marker file exists (proves same container was restarted)
7. Cleanup
"""

import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    get_container_list,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    with_live_screen,
    write_workspace_container_config,
)


def test_persistent_resume_reuses_stopped_container(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that --resume restarts the original stopped container, not a fresh one.

    The marker file /var/tmp/persist-marker-Coi-TEST is created inside the container
    during the first session. It lives outside ~/.claude and the workspace, so it
    can only survive if the same container is restarted (not recreated from image).

    If a new container is created on a different slot, the marker file won't exist.
    """
    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    # Persistence is config-driven: [container] persistent = true
    write_workspace_container_config(workspace_dir, persistent=True)

    # === Phase 1: Start persistent session and create marker ===

    child = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    # Exit CLI to bash
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(2)

    # Wait for bash prompt
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

    # Create a marker file outside workspace and config dirs
    # This simulates system-level state (like apt-installed packages)
    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send("touch /var/tmp/persist-marker-Coi-TEST && echo MARKER_CREATED_999")
        time.sleep(0.5)
        child.send("\x0d")
        time.sleep(2)
        marker_created = wait_for_text_in_monitor(monitor, "MARKER_CREATED_999", timeout=10)
        assert marker_created, "Marker file should have been created"

    # Poweroff container (stays stopped in persistent mode)
    child.send("sudo poweroff")
    time.sleep(0.3)
    child.send("\x0d")

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

    # Give time for cleanup handler
    time.sleep(3)

    # Verify session was saved
    assert "Session data saved" in output1 or "Saving session data" in output1, (
        f"Session should be saved. Got:\n{output1}"
    )

    # Verify the stopped container still exists (persistent mode keeps it)
    containers = get_container_list()
    assert container_name in containers, (
        f"Container {container_name} should still exist (stopped) after poweroff "
        f"in persistent mode. Containers: {containers}"
    )

    # === Phase 2: Resume and verify same container is reused ===

    child2 = spawn_coi(
        coi_binary,
        ["shell", "--resume"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child2, timeout=60)
    wait_for_prompt(child2, timeout=90)

    # Exit CLI to bash to check for marker
    child2.send("exit")
    time.sleep(0.3)
    child2.send("\x0d")
    time.sleep(2)

    # Wait for bash prompt
    time.sleep(3)

    # Check if marker file exists — this proves the same container was restarted
    # Use $? expansion so the sentinel string only appears in the output, not in
    # the echoed command line (which would cause false matches in the monitor).
    with with_live_screen(child2) as monitor:
        time.sleep(1)
        child2.send("test -f /var/tmp/persist-marker-Coi-TEST; echo MARKER_EXIT_${?}_END")
        time.sleep(0.5)
        child2.send("\x0d")
        time.sleep(2)
        marker_found = wait_for_text_in_monitor(monitor, "MARKER_EXIT_0_END", timeout=10)

    # Get output for debugging
    if hasattr(child2.logfile_read, "get_raw_output"):
        output2 = child2.logfile_read.get_raw_output()
    elif hasattr(child2.logfile_read, "get_display_stripped"):
        output2 = child2.logfile_read.get_display_stripped()
    else:
        output2 = ""

    # === Phase 3: Cleanup ===

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

    time.sleep(3)

    # Force delete all possible containers (slot 1 and slot 2)
    for slot in [1, 2]:
        cn = calculate_container_name(workspace_dir, slot)
        subprocess.run(
            [coi_binary, "container", "delete", cn, "--force"],
            capture_output=True,
            timeout=30,
        )

    # Verify containers are gone
    time.sleep(1)
    containers = get_container_list()
    for slot in [1, 2]:
        cn = calculate_container_name(workspace_dir, slot)
        assert cn not in containers, f"Container {cn} should be deleted after cleanup"

    # Assert marker was found — proves the original container was restarted
    assert marker_found, (
        f"Marker file /var/tmp/persist-marker-Coi-TEST should exist in resumed container, "
        f"proving the original stopped container was restarted (not a fresh one created). "
        f"marker_found={marker_found}. "
        f"Output:\n{output2}"
    )
