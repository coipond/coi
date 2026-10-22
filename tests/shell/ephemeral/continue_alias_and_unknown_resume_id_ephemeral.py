"""
Test for coi shell --continue (the alias of --resume) and an unknown --resume id.

Tests that:
1. A first `coi shell --background` saves one session for the workspace
2. `coi shell --continue` auto-detects that session, like --resume
3. `coi shell --continue=<id>` resumes that session, like --resume=<id>
4. `coi shell --resume=<bogus>` fails with "session '<bogus>' not found - check
   available sessions with: coi list --all" and creates no container

A fake HOME keeps the saved sessions (~/.coi/sessions-claude) to this test.
"""

import json
import os
import subprocess

from support.helpers import calculate_container_name, get_container_list

BOGUS_ID = "no-such-session-49157"


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


def _kill_workspace_containers(coi_binary, workspace_dir, env):
    running = _workspace_containers(workspace_dir)
    assert running, "the session started no container for the workspace"
    for name in running:
        result = subprocess.run(
            [coi_binary, "kill", "--force", name],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        assert result.returncode == 0, f"coi kill {name} failed:\n{result.stderr}"


def _saved_sessions(sessions_dir, workspace_dir):
    """IDs of the saved sessions whose metadata names workspace_dir."""
    ids = []
    if not sessions_dir.is_dir():
        return ids
    for entry in sessions_dir.iterdir():
        metadata = entry / "metadata.json"
        if (
            metadata.is_file()
            and json.loads(metadata.read_text()).get("workspace") == workspace_dir
        ):
            ids.append(entry.name)
    return ids


def test_continue_alias_and_unknown_resume_id(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    --continue and --continue=<id> resume like --resume; an unknown --resume id
    fails with a hint and launches nothing.

    Flow:
    1. coi shell --background, then coi kill: one saved session
    2. coi shell --background --continue: "Auto-detected session: <id>"
    3. coi shell --background --continue=<id>: "Resuming session: <id>"
    4. coi shell --background --resume=<bogus>: non-zero exit, the not-found
       message, no container for the workspace
    """
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    env = {**os.environ, "HOME": str(fake_home), "COI_USE_DUMMY": "1"}
    sessions_dir = fake_home / ".coi" / "sessions-claude"

    # === Phase 1: one saved session ===

    result = _shell(coi_binary, workspace_dir, env, "--slot", "1")
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
    _kill_workspace_containers(coi_binary, workspace_dir, env)

    saved = _saved_sessions(sessions_dir, workspace_dir)
    assert len(saved) == 1, f"expected one saved session for the workspace, got: {saved}"
    session_id = saved[0]

    # === Phase 2: --continue auto-detects it ===

    result = _shell(coi_binary, workspace_dir, env, "--continue")
    assert result.returncode == 0, f"coi shell --continue failed:\n{result.stderr}"
    assert f"Auto-detected session: {session_id}" in result.stderr, (
        f"--continue should auto-detect session {session_id}, like --resume:\n{result.stderr}"
    )
    _kill_workspace_containers(coi_binary, workspace_dir, env)

    # === Phase 3: --continue=<id> resumes that session ===

    result = _shell(coi_binary, workspace_dir, env, f"--continue={session_id}")
    assert result.returncode == 0, f"coi shell --continue={session_id} failed:\n{result.stderr}"
    assert f"Resuming session: {session_id}" in result.stderr, (
        f"--continue=<id> should resume session {session_id}, like --resume=<id>:\n{result.stderr}"
    )
    _kill_workspace_containers(coi_binary, workspace_dir, env)

    # === Phase 4: an unknown --resume id fails with a hint ===

    result = _shell(coi_binary, workspace_dir, env, f"--resume={BOGUS_ID}")
    assert result.returncode != 0, (
        f"--resume={BOGUS_ID} should fail, got exit 0:\n{result.stdout}\n{result.stderr}"
    )
    expected = f"session '{BOGUS_ID}' not found - check available sessions with: coi list --all"
    assert expected in result.stdout + result.stderr, (
        f"expected {expected!r} in the output, got:\n{result.stdout}\n{result.stderr}"
    )
    leftover = _workspace_containers(workspace_dir)
    assert not leftover, f"an unknown --resume id should create no container, found: {leftover}"
