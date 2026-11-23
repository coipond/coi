"""
Test for coi persist - a container started with another tool's profile.

Tests that:
1. A session launched with a profile whose [tool] name is not the configured
   tool keeps its metadata in that tool's sessions dir
2. `coi persist` finds it there, succeeds, marks the metadata persistent and
   sets user.coi.persistent=true
"""

import json
import os
import subprocess
from pathlib import Path

from support.helpers import (
    container_config_get,
    session_for_container,
    start_background_shell,
    write_profile,
)


def _codex_metadata(container_name):
    """Return the saved codex session metadata naming the container."""
    sessions_dir = Path.home() / ".coi" / "sessions-codex"
    session_id = session_for_container(sessions_dir, container_name)
    if session_id is None:
        return None
    return json.loads((sessions_dir / session_id / "metadata.json").read_text())


def test_persist_finds_other_tool_metadata(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. coi shell --background --profile <codex profile>
    2. coi persist <container> with the default tool configured
    3. persist succeeds; codex metadata and container key say persistent
    """
    write_profile(workspace_dir, "codex-persist", '[tool]\nname = "codex"\n')
    env = {**os.environ, "COI_USE_DUMMY": "1"}
    container_name, _ = start_background_shell(
        coi_binary, workspace_dir, env, profile="codex-persist", slot=1
    )
    metadata = _codex_metadata(container_name)
    assert metadata is not None, "no codex session metadata for the container"
    assert not metadata.get("persistent"), "session should start ephemeral"

    result = subprocess.run(
        [coi_binary, "persist", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"persist should succeed. output: {result.stdout + result.stderr}"
    )

    assert _codex_metadata(container_name).get("persistent") is True, (
        "codex metadata should be persistent"
    )
    assert container_config_get(container_name, "user.coi.persistent") == "true"
