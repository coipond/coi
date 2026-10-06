"""
Test for coi shell --resume=<session-id> - resume a specific opencode session by ID.

Tests that sessions saved with [tool] name = "opencode" can be resumed by
explicit session ID. The opencode tool stores its config under .config/opencode
(not .claude), so this verifies that session detection is tool-agnostic.

Flow:
1. Write .coi/config.toml with [tool] name = "opencode"
2. Start a session and create some state
3. Exit and save session
4. Get the session ID from coi list --all
5. Resume by specific session ID with --resume=<uuid>
6. Verify correct session was resumed
"""

import re
import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    send_prompt,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    wait_for_text_on_screen,
    with_live_screen,
)


def test_resume_specific_opencode_session(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that --resume=<session-id> resumes the specified opencode session.

    This is the opencode variant of resume_specific_session_ephemeral.py.
    It verifies that --resume=<uuid> works when the tool is opencode.
    """
    import os

    # Write .coi/config.toml to select opencode as the tool
    config_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config.toml")
    with open(config_path, "w") as f:
        f.write('[tool]\nname = "opencode"\n')

    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Create first session ===

    child1 = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child1, timeout=60)
    wait_for_prompt(child1, timeout=90)

    # Interact to create session state
    with with_live_screen(child1) as monitor:
        time.sleep(2)
        send_prompt(child1, "first session marker")
        responded = wait_for_text_in_monitor(monitor, "first session marker-BACK", timeout=30)
        assert responded, "First session should respond"

    # Poweroff to save session
    child1.send("exit")
    time.sleep(0.3)
    child1.send("\x0d")
    time.sleep(2)
    child1.send("sudo poweroff")
    time.sleep(0.3)
    child1.send("\x0d")

    try:
        child1.expect(EOF, timeout=60)
    except TIMEOUT:
        pass

    try:
        child1.close(force=False)
    except Exception:
        child1.close(force=True)

    time.sleep(5)

    # === Phase 2: Get first session ID ===

    # List sessions to find the first one
    result = subprocess.run(
        [coi_binary, "list", "--all"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
    )

    # Parse session ID from output (look for session IDs in Saved Sessions section)
    first_session_id = None
    lines = result.stdout.split("\n")
    in_sessions_section = False
    uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    current_uuid = None
    for line in lines:
        if "Saved Sessions:" in line:
            in_sessions_section = True
            continue
        if in_sessions_section:
            stripped = line.strip()
            # Check if line starts with a UUID
            parts = stripped.split()
            if parts and uuid_pattern.match(parts[0]):
                current_uuid = parts[0]
            # Check if this line shows the workspace for current UUID
            elif current_uuid and "Workspace:" in line and workspace_dir in line:
                first_session_id = current_uuid
                break

    assert first_session_id is not None, (
        f"Should find session for workspace {workspace_dir} in output:\n{result.stdout}"
    )

    # === Phase 3: Resume first session by specific ID ===

    child3 = spawn_coi(
        coi_binary,
        ["shell", f"--resume={first_session_id}"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child3, timeout=60)

    # Should see "Resuming session" message
    try:
        wait_for_text_on_screen(child3, "Resuming session", timeout=30)
        resumed = True
    except TimeoutError:
        resumed = False
    # For opencode the line comes from coi's setup log, printed before the tmux
    # attach takes over the screen; a fast setup can clear it from the screen
    # before the poll sees it. Also accept it in the full captured output.
    if not resumed and hasattr(child3.logfile_read, "get_raw_output"):
        resumed = "Resuming session" in child3.logfile_read.get_raw_output()

    # === Phase 4: Cleanup ===

    child3.send("exit")
    time.sleep(0.3)
    child3.send("\x0d")
    time.sleep(2)
    child3.send("sudo poweroff")
    time.sleep(0.3)
    child3.send("\x0d")

    try:
        child3.expect(EOF, timeout=60)
    except TIMEOUT:
        pass

    try:
        child3.close(force=False)
    except Exception:
        child3.close(force=True)

    time.sleep(3)

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )

    # Assert specific session was resumed
    assert resumed, f"Should resume specific opencode session {first_session_id}"
