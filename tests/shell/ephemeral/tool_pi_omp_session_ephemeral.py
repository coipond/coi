"""
Test that coi shell with [tool] name = "pi" / "omp" sets up the tool's session.

Tests that, for each tool:
1. ~/<config dir>/APPEND_SYSTEM.md is a symlink to ~/SANDBOX_CONTEXT.md
2. The session dir variable (PI_CODING_AGENT_SESSION_DIR / OMP_SESSION_DIR)
   points at <workspace>/.pi-sessions (.omp-sessions)
3. The host config bundle (AGENTS.md, settings.json) is copied into the
   config dir
4. The tool is launched without --continue, and with --continue on --resume

A recorder script stands in for the tool via [tool] binary (trusted scope). It
writes what it saw at launch to a marker file in the workspace, then stays
alive like an agent would. COI_USE_DUMMY is not set: it would replace the
launched binary.
"""

import json
import subprocess
import time
from pathlib import Path

import pytest

from support.helpers import calculate_container_name, write_trusted_coi_config

MARKER = ".coi-tool-session-marker"
CONTAINER_HOME = "/home/code"

TOOLS = {
    "pi": {"config_dir": ".pi/agent", "session_env": "PI_CODING_AGENT_SESSION_DIR"},
    "omp": {"config_dir": ".omp", "session_env": "OMP_SESSION_DIR"},
}

RECORDER = """#!/bin/sh
cfg="{home}/{config_dir}"
out="$(dirname "$0")/{marker}"
{{
    printf 'argv=%s\\n' "$*"
    printf 'session_dir=%s\\n' "${session_env}"
    printf 'append_system=%s\\n' "$(readlink "$cfg/APPEND_SYSTEM.md")"
    printf 'agents=%s\\n' "$(cat "$cfg/AGENTS.md")"
    printf 'settings=%s\\n' "$(tr -d '\\n' < "$cfg/settings.json")"
}} > "$out.tmp"
mv "$out.tmp" "$out"
exec sleep 300
"""


def _launch(coi_binary, workspace_dir, env, marker, *extra):
    if marker.exists():
        marker.unlink()
    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1", *extra],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, f"coi shell --background {extra} failed:\n{result.stderr}"

    # The tool starts inside tmux shortly after the container is ready.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(1)
    assert marker.exists(), f"the tool was not launched (no marker). coi stderr:\n{result.stderr}"

    recorded = {}
    for line in marker.read_text().splitlines():
        key, _, value = line.partition("=")
        recorded[key] = value
    return recorded


@pytest.mark.parametrize("tool_name", sorted(TOOLS))
def test_pi_omp_session_setup(coi_binary, cleanup_containers, workspace_dir, tmp_path, tool_name):
    """
    coi shell with [tool] name = "pi" / "omp" links the sandbox context, sets the
    session dir, seeds the config bundle and passes --continue only on --resume.

    Flow:
    1. Write host config (AGENTS.md, settings.json) into a fake HOME
    2. Configure [tool] name and binary = the recorder script (trusted scope)
    3. coi shell --background: check the recorded launch state
    4. coi kill the container, then coi shell --background --resume: check
       that the tool got --continue
    """
    spec = TOOLS[tool_name]
    container_name = calculate_container_name(workspace_dir, 1)

    fake_home = tmp_path / "fake_home"
    host_cfg = fake_home / spec["config_dir"]
    host_cfg.mkdir(parents=True)
    (host_cfg / "AGENTS.md").write_text(f"host agents for {tool_name}")
    (host_cfg / "settings.json").write_text(json.dumps({"userSetting": "kept"}))

    script = Path(workspace_dir) / "fake-agent.sh"
    script.write_text(
        RECORDER.format(
            home=CONTAINER_HOME,
            config_dir=spec["config_dir"],
            marker=MARKER,
            session_env=spec["session_env"],
        )
    )
    script.chmod(0o755)
    marker = Path(workspace_dir) / MARKER

    env = write_trusted_coi_config(
        f'[tool]\nname = "{tool_name}"\nbinary = "/workspace/fake-agent.sh"\n'
    )
    env.pop("COI_USE_DUMMY", None)
    env["HOME"] = str(fake_home)

    # === Phase 1: new session ===

    recorded = _launch(coi_binary, workspace_dir, env, marker)

    assert recorded.get("append_system") == f"{CONTAINER_HOME}/SANDBOX_CONTEXT.md", (
        f"~/{spec['config_dir']}/APPEND_SYSTEM.md should link to ~/SANDBOX_CONTEXT.md: {recorded}"
    )
    assert recorded.get("session_dir") == f"/workspace/.{tool_name}-sessions", (
        f"{spec['session_env']} should point at the workspace: {recorded}"
    )
    assert recorded.get("agents") == f"host agents for {tool_name}", (
        f"host AGENTS.md was not copied into ~/{spec['config_dir']}: {recorded}"
    )
    settings = json.loads(recorded.get("settings") or "{}")
    assert settings.get("userSetting") == "kept", (
        f"host settings.json was not copied into ~/{spec['config_dir']}: {recorded}"
    )
    assert "--continue" not in recorded.get("argv", "").split(), (
        f"a new session must not pass --continue: {recorded}"
    )

    result = subprocess.run(
        [coi_binary, "kill", "--force", container_name],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, f"coi kill failed:\n{result.stderr}"

    # === Phase 2: resume ===

    recorded = _launch(coi_binary, workspace_dir, env, marker, "--resume")

    assert "--continue" in recorded.get("argv", "").split(), (
        f"--resume should launch {tool_name} with --continue: {recorded}"
    )
    assert recorded.get("session_dir") == f"/workspace/.{tool_name}-sessions", (
        f"{spec['session_env']} should point at the workspace on resume: {recorded}"
    )
