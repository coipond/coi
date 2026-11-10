"""
Test for coi tmux send and coi shell --background into a running session -
both leave tmux copy mode before they type the command.

Follow-up to https://github.com/coipond/coi/issues/930: with mouse mode on, a
wheel scroll leaves the pane in copy mode, which swallowed the keys of a
command sent into it.

Tests that:
1. `coi tmux send` runs the command in a pane in copy mode, and the pane is no
   longer in copy mode
2. `coi shell --background --resume` into the running session sends the tool
   command to a pane in copy mode, the tool starts, and the pane is no longer
   in copy mode
"""

import json
import subprocess
import time
from pathlib import Path

from support.helpers import (
    calculate_container_name,
    make_workspace_writable,
    write_trusted_coi_config,
)

AGENT_MARKER = ".coi-agent-runs"
SEND_MARKER = ".coi-tmux-send-ran"

FAKE_AGENT = f"""#!/bin/sh
# Stand-in for the agent CLI: record each start, then exit to the pane's bash.
echo started >> "$(dirname "$0")/{AGENT_MARKER}"
"""


def _shell(coi_binary, workspace_dir, env, *args):
    return subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, *args],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )


def _tmux(coi_binary, container_name, *args):
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--user",
            "1000",
            "--",
            "tmux",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"tmux {args[0]} should succeed. stderr: {result.stderr}"
    return result.stdout + result.stderr


def _in_mode(coi_binary, container_name, target):
    return _tmux(coi_binary, container_name, "display", "-p", "-t", target, "#{pane_in_mode}")


def _enter_copy_mode(coi_binary, container_name, target):
    _tmux(coi_binary, container_name, "copy-mode", "-t", target)
    assert _in_mode(coi_binary, container_name, target).strip() == "1", (
        "the pane should be in copy mode"
    )


def _wait_for(predicate, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not predicate():
        time.sleep(1)
    return predicate()


def _agent_runs(workspace_dir):
    marker = Path(workspace_dir) / AGENT_MARKER
    return len(marker.read_text().splitlines()) if marker.exists() else 0


def _session_for_container(sessions_dir, container_name):
    for metadata in sessions_dir.glob("*/metadata.json"):
        if json.loads(metadata.read_text()).get("container_name") == container_name:
            return metadata.parent.name
    return None


def test_tmux_send_leaves_copy_mode(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    A command sent with coi tmux send or coi shell --background into a pane in
    copy mode runs, and the pane leaves copy mode.

    Flow:
    1. coi shell --background with a stand-in tool that records its start and
       exits, so the pane falls back to bash
    2. Put the pane in copy mode, coi tmux send a command that writes a
       marker, check the marker and that copy mode is off
    3. Put the pane in copy mode again, coi shell --background --resume into
       the running session, check the tool started again and copy mode is off
    4. Cleanup
    """
    script = Path(workspace_dir) / "fake-agent.sh"
    script.write_text(FAKE_AGENT)
    script.chmod(0o755)
    make_workspace_writable(workspace_dir)

    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    env = write_trusted_coi_config('[tool]\nbinary = "/workspace/fake-agent.sh"\n')
    env["HOME"] = str(fake_home)
    env.pop("COI_USE_DUMMY", None)
    sessions_dir = fake_home / ".coi" / "sessions-claude"

    container_name = calculate_container_name(workspace_dir, 1)
    pane = f"coi-{container_name}"

    # === Phase 1: Start the session; the tool exits to bash ===

    result = _shell(coi_binary, workspace_dir, env, "--slot", "1")
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
    assert _wait_for(lambda: _agent_runs(workspace_dir) == 1), "the tool never started"
    time.sleep(1)

    # === Phase 2: coi tmux send to a pane in copy mode ===

    _enter_copy_mode(coi_binary, container_name, pane)

    result = subprocess.run(
        [coi_binary, "tmux", "send", container_name, f"touch /workspace/{SEND_MARKER}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Tmux send should succeed. stderr: {result.stderr}"

    assert _wait_for(lambda: (Path(workspace_dir) / SEND_MARKER).exists(), timeout=15), (
        "coi tmux send to a pane in copy mode must run the command"
    )
    assert _in_mode(coi_binary, container_name, pane).strip() == "0", (
        "coi tmux send must leave copy mode"
    )

    # === Phase 3: coi shell --background into the running session ===

    session_id = _session_for_container(sessions_dir, container_name)
    assert session_id, f"no saved session for {container_name} in {sessions_dir}"

    _enter_copy_mode(coi_binary, container_name, pane)

    result = _shell(coi_binary, workspace_dir, env, f"--resume={session_id}")
    assert result.returncode == 0, f"coi shell --background --resume failed:\n{result.stderr}"
    assert "Sent command to existing tmux session" in result.stderr, (
        f"coi shell should send the tool command into the running session:\n{result.stderr}"
    )

    assert _wait_for(lambda: _agent_runs(workspace_dir) == 2, timeout=15), (
        "coi shell --background into a pane in copy mode must start the tool"
    )
    assert _in_mode(coi_binary, container_name, pane).strip() == "0", (
        "coi shell --background into the running session must leave copy mode"
    )

    # === Phase 4: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
