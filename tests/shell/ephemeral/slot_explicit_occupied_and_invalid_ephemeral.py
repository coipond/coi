"""
Test explicit --slot handling: an invalid slot, an occupied slot, and resume to
the session's original slot.

Tests that:
1. `coi shell --slot -1` and `coi run --slot -1` fail with a usage error (exit
   2) and create no container
2. `coi shell --slot 1` while slot 1 runs prints "Slot 1 is occupied, using
   slot 2 instead" and starts slot 2
3. Resuming the slot-2 session without --slot prints "Reusing original slot 2
   from session" and starts slot 2, even when slot 1 is free

A fake HOME keeps the saved sessions (~/.coi/sessions-claude) to this test.
"""

import json
import os
import subprocess

from support.helpers import calculate_container_name, get_container_list

INVALID_SLOT_MESSAGE = "invalid --slot -1: use a positive slot number, or 0 to auto-allocate"


def _shell(coi_binary, workspace_dir, env, *args):
    return subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, *args],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )


def _workspace_containers(workspace_dir):
    names = {calculate_container_name(workspace_dir, slot) for slot in range(1, 11)}
    return names & set(get_container_list())


def _kill(coi_binary, env, *names):
    for name in names:
        result = subprocess.run(
            [coi_binary, "kill", "--force", name],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        assert result.returncode == 0, f"coi kill {name} failed:\n{result.stderr}"


def _session_for_container(sessions_dir, container_name):
    for entry in sessions_dir.iterdir():
        metadata = entry / "metadata.json"
        if (
            metadata.is_file()
            and json.loads(metadata.read_text()).get("container_name") == container_name
        ):
            return entry.name
    return None


def test_slot_explicit_occupied_and_invalid(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    --slot -1 is a usage error; an occupied --slot moves to the next free slot;
    resume returns to the session's original slot.

    Flow:
    1. coi shell / coi run --slot -1: exit 2, the usage message, no container
    2. coi shell --background --slot 1, twice: the second moves to slot 2
    3. coi kill both, then coi shell --background --resume=<slot-2 session>:
       "Reusing original slot 2 from session", slot 2 runs, slot 1 does not
    """
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    env = {**os.environ, "HOME": str(fake_home), "COI_USE_DUMMY": "1"}
    sessions_dir = fake_home / ".coi" / "sessions-claude"
    slot1 = calculate_container_name(workspace_dir, 1)
    slot2 = calculate_container_name(workspace_dir, 2)

    # === Phase 1: --slot -1 is rejected ===

    result = _shell(coi_binary, workspace_dir, env, "--slot", "-1")
    assert result.returncode == 2, (
        f"coi shell --slot -1 should exit 2, got {result.returncode}:\n{result.stderr}"
    )
    assert INVALID_SLOT_MESSAGE in result.stderr, f"unexpected output:\n{result.stderr}"

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--slot", "-1", "--", "true"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 2, (
        f"coi run --slot -1 should exit 2, got {result.returncode}:\n{result.stderr}"
    )
    assert INVALID_SLOT_MESSAGE in result.stderr, f"unexpected output:\n{result.stderr}"

    invalid_name = slot1.removesuffix("-1") + "--1"
    leftover = _workspace_containers(workspace_dir) | ({invalid_name} & set(get_container_list()))
    assert not leftover, f"--slot -1 should create no container, found: {leftover}"

    # === Phase 2: an occupied explicit slot moves to the next free one ===

    result = _shell(coi_binary, workspace_dir, env, "--slot", "1")
    assert result.returncode == 0, f"coi shell --slot 1 failed:\n{result.stderr}"
    assert slot1 in _workspace_containers(workspace_dir), f"{slot1} should be running"

    result = _shell(coi_binary, workspace_dir, env, "--slot", "1")
    assert result.returncode == 0, f"second coi shell --slot 1 failed:\n{result.stderr}"
    assert "Slot 1 is occupied, using slot 2 instead" in result.stderr, (
        f"expected the occupied-slot message:\n{result.stderr}"
    )
    assert slot2 in _workspace_containers(workspace_dir), f"{slot2} should be running"

    session_id = _session_for_container(sessions_dir, slot2)
    assert session_id, f"no saved session for {slot2} in {sessions_dir}"

    # === Phase 3: resume returns to the original slot ===

    _kill(coi_binary, env, slot1, slot2)

    result = _shell(coi_binary, workspace_dir, env, f"--resume={session_id}")
    assert result.returncode == 0, f"coi shell --resume={session_id} failed:\n{result.stderr}"
    assert "Reusing original slot 2 from session" in result.stderr, (
        f"resume without --slot should reuse slot 2:\n{result.stderr}"
    )
    running = _workspace_containers(workspace_dir)
    assert running == {slot2}, f"only {slot2} should be running after resume, got: {running}"
