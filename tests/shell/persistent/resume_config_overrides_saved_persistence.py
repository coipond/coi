"""
Test for coi shell --resume - an explicit [container] persistent in config
overrides the persistence saved with the session.

Tests that, in both directions (persistent session resumed with
persistent = false, ephemeral session resumed with persistent = true):
1. The resume prints "Config [container] persistent = <value> overrides the
   session's saved mode"
2. A persistent session resumed as ephemeral does not print "Inherited
   persistent mode from session"
3. The resumed session takes the configured mode: its saved metadata and
   `coi list` show it

A fake HOME keeps the saved sessions (~/.coi/sessions-claude) to this test.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from support.helpers import calculate_container_name


def _write_persistence(workspace_dir, persistent):
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(parents=True, exist_ok=True)
    value = "true" if persistent else "false"
    (coi_dir / "config.toml").write_text(f"[container]\npersistent = {value}\n")


def _shell(coi_binary, workspace_dir, env, *args):
    return subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, *args],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        cwd=workspace_dir,
    )


def _kill(coi_binary, container_name, env):
    result = subprocess.run(
        [coi_binary, "kill", "--force", container_name],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, f"coi kill {container_name} failed:\n{result.stderr}"


def _list_mode(coi_binary, container_name, env):
    result = subprocess.run(
        [coi_binary, "list"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, f"coi list failed:\n{result.stderr}"
    for line in result.stdout.splitlines():
        if container_name in line:
            return line
    raise AssertionError(f"{container_name} not in coi list output:\n{result.stdout}")


@pytest.mark.parametrize("saved_persistent", [True, False], ids=["persistent", "ephemeral"])
def test_resume_config_overrides_saved_persistence(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, saved_persistent
):
    """
    Resuming with the opposite [container] persistent in config switches the
    session's mode and says so.

    Flow:
    1. Config persistent = <saved>; coi shell --background; coi kill
    2. Config persistent = <not saved>; coi shell --background --resume=<id>
    3. Check the override message, the session metadata and coi list
    """
    configured = not saved_persistent
    container_name = calculate_container_name(workspace_dir, 1)

    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    env = {**os.environ, "HOME": str(fake_home), "COI_USE_DUMMY": "1"}
    sessions_dir = fake_home / ".coi" / "sessions-claude"

    # === Phase 1: save a session in the original mode ===

    _write_persistence(workspace_dir, saved_persistent)
    result = _shell(coi_binary, workspace_dir, env, "--slot", "1")
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
    _kill(coi_binary, container_name, env)

    sessions = [p for p in sessions_dir.iterdir() if (p / "metadata.json").is_file()]
    assert len(sessions) == 1, f"expected one saved session, got: {sessions}"
    metadata_path = sessions[0] / "metadata.json"
    assert json.loads(metadata_path.read_text())["persistent"] is saved_persistent, (
        f"the first session should be saved with persistent = {saved_persistent}"
    )

    # === Phase 2: resume with the opposite mode in config ===

    _write_persistence(workspace_dir, configured)
    result = _shell(coi_binary, workspace_dir, env, f"--resume={sessions[0].name}")
    assert result.returncode == 0, f"coi shell --resume failed:\n{result.stderr}"

    value = "true" if configured else "false"
    assert f"Config [container] persistent = {value} overrides the session's saved mode" in (
        result.stderr
    ), f"expected the override message:\n{result.stderr}"
    if not configured:
        assert "Inherited persistent mode from session" not in result.stderr, (
            f"a session resumed as ephemeral must not inherit persistence:\n{result.stderr}"
        )

    # === Phase 3: the resumed session has the configured mode ===

    assert json.loads(metadata_path.read_text())["persistent"] is configured, (
        f"the resumed session should be saved with persistent = {configured}"
    )
    line = _list_mode(coi_binary, container_name, env)
    expected, unexpected = (
        ("(persistent)", "(ephemeral)") if configured else ("(ephemeral)", "(persistent)")
    )
    assert expected in line and unexpected not in line, (
        f"coi list should show {container_name} as {expected}. Line: {line}"
    )
