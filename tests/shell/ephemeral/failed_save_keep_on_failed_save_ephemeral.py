"""
Test for coi shell - a failed session save on poweroff, with and without
[container] keep_on_failed_save.

Tests that:
- default: the stopped container is removed, and coi says why the save failed
  and that the conversation since the last saved copy is lost
- keep_on_failed_save = true: the stopped container is kept, and coi says how
  to save it (coi shell --resume=<session-id>) or remove it (coi kill / coi clean)

Flow:
  start coi shell, exit the dummy to bash, replace the session's saved dir on
  the host with a file (the save then cannot create it), sudo poweroff
"""

import subprocess
from pathlib import Path

import pytest
from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    child_output,
    exit_cli_to_bash,
    incus_status,
    session_for_container,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_specific_container_deletion,
)

SESSIONS_DIR = Path.home() / ".coi" / "sessions-claude"


@pytest.mark.parametrize("keep", [False, True], ids=["default", "keep"])
def test_failed_save_on_poweroff(coi_binary, cleanup_containers, workspace_dir, keep):
    if keep:
        config_dir = Path(workspace_dir) / ".coi"
        config_dir.mkdir(exist_ok=True)
        (config_dir / "config.toml").write_text("[container]\nkeep_on_failed_save = true\n")
    container_name = calculate_container_name(workspace_dir, 1)

    child = spawn_coi(
        coi_binary, ["shell"], cwd=workspace_dir, env={"COI_USE_DUMMY": "1"}, timeout=120
    )
    session_dir = None
    moved = None
    try:
        wait_for_container_ready(child, timeout=60)
        wait_for_prompt(child, timeout=90)
        exit_cli_to_bash(child)

        # The session's metadata is saved at start; a file in place of its
        # dir makes the save at cleanup fail.
        session_id = session_for_container(SESSIONS_DIR, container_name)
        assert session_id, f"no saved session metadata names {container_name}"
        session_dir = SESSIONS_DIR / session_id
        moved = session_dir.with_name(session_id + ".moved")
        session_dir.rename(moved)
        session_dir.write_text("")

        child.send("sudo poweroff")
        child.send("\x0d")
        try:
            child.expect(EOF, timeout=120)
        except TIMEOUT:
            pass
        output = child_output(child)
        child.close(force=True)

        assert "Failed to save session data" in output, f"the save should fail. Output:\n{output}"
        if keep:
            status = incus_status(container_name)
            assert status == "STOPPED", f"container should be kept stopped, got {status!r}"
            assert "Container kept (stopped) - session data could NOT be saved" in output, output
            assert f"coi shell --resume={session_id}" in output, output
            assert f"coi kill {container_name}" in output, output
        else:
            assert wait_for_specific_container_deletion(container_name, timeout=30), (
                f"container {container_name} should be removed"
            )
            assert "the conversation since the last saved copy is lost" in output, output
    finally:
        if moved is not None and moved.exists():
            session_dir.unlink(missing_ok=True)
            moved.rename(session_dir)
        elif session_dir is not None and session_dir.is_file():
            session_dir.unlink()
        if not child.closed:
            child.close(force=True)
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
            check=False,
        )
