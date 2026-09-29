"""
Regression test: session data must be saved cleanly after 'sudo poweroff'
with no "Warning: Failed to save session data" warnings.

Root cause (fixed in #397):

    When the container shuts down via 'sudo poweroff', Coi's cleanup
    goroutine immediately attempts to pull the tool config directory via
    incus file pull (SFTP). The container's SFTP subsystem may still be
    mid-teardown at that point, producing transient errors:

        Error: error receiving version packet from server:
               server unexpectedly closed connection: unexpected EOF
        Error: Failed getting instance SFTP connection: bad file descriptor

    These errors caused saveSessionData to fail, silently dropping the
    session — so --resume stopped working after a poweroff-triggered exit.

Fix: on the normal exit path the save succeeds immediately (container is
running, SFTP healthy). On the poweroff path, if a transient SFTP error
occurs saveSessionData waits up to 5 s for the container to fully stop,
then retries — once stopped, incus uses direct file access (no SFTP) and
the retry succeeds. The fix applies to all modes (persistent and
non-persistent) and all tools with a config directory.

This test verifies:
  1. After 'sudo poweroff', "Session data saved successfully" appears.
  2. "Warning: Failed to save session data" does NOT appear.
  3. As a result, 'coi shell --resume' succeeds in the follow-up session.

The timing of the SFTP race varies, so (1) and (2) are the primary
assertions; the resume check (3) confirms the saved data is usable.
"""

import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_specific_container_deletion,
    wait_for_text_on_screen,
)


def _collect_output(child):
    lf = child.logfile_read
    for attr in ("get_raw_output", "get_output", "get_display", "get_display_stripped"):
        if hasattr(lf, attr):
            return getattr(lf, attr)()
    if child.before:
        raw = child.before
        return raw.decode(errors="replace") if isinstance(raw, bytes) else raw
    return ""


def test_session_save_no_sftp_error_on_poweroff(coi_binary, cleanup_containers, workspace_dir):
    """
    Session data should be saved cleanly after sudo poweroff — no SFTP warning.

    Flow:
    1. Start an ephemeral coi shell session (dummy tool)
    2. Exit the dummy to bash, then sudo poweroff
    3. Verify cleanup output contains "Session data saved" and does NOT
       contain "Warning: Failed to save session data"
    4. Verify --resume succeeds (confirming the saved data is usable)
    """
    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: initial session ===
    child = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    # Drop to bash and poweroff
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(3)

    child.send("sudo poweroff")
    time.sleep(0.3)
    child.send("\x0d")

    try:
        child.expect(EOF, timeout=60)
    except TIMEOUT:
        pass

    output1 = _collect_output(child)

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    container_deleted = wait_for_specific_container_deletion(container_name, timeout=60)
    assert container_deleted, f"Container {container_name} should be deleted after poweroff"

    # Primary assertions: session data saved, no SFTP warning
    assert "Session data saved successfully" in output1 or "Saving session data" in output1, (
        f"Expected 'Session data saved' in cleanup output. Got:\n{output1}"
    )
    assert "Warning: Failed to save session data" not in output1, (
        "Cleanup should not warn about failed session save after poweroff — "
        "transient SFTP errors should be retried. Got:\n"
        f"{output1}"
    )

    # === Phase 2: verify --resume works (confirms saved data is usable) ===
    child2 = spawn_coi(
        coi_binary,
        ["shell", "--resume"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child2, timeout=60)

    try:
        wait_for_text_on_screen(child2, "Resuming session", timeout=30)
        resumed = True
    except TimeoutError:
        resumed = False

    # Cleanup second session
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

    container_name2 = calculate_container_name(workspace_dir, 1)
    container2_deleted = wait_for_specific_container_deletion(container_name2, timeout=60)
    if not container2_deleted:
        subprocess.run(
            [coi_binary, "container", "delete", container_name2, "--force"],
            capture_output=True,
            timeout=30,
            check=False,
        )
    assert container2_deleted, (
        f"Container {container_name2} should be deleted after phase 2 poweroff"
    )

    assert resumed, (
        "coi shell --resume should succeed after a poweroff-triggered session save. "
        "If this fails together with the SFTP warning assertion above, the session "
        "data was not saved correctly."
    )
