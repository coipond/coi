"""
Test that coi shell with [tool] name = "pi" / "omp" sets up the tool's session.

Tests that, for each tool:
1. ~/<agent dir>/APPEND_SYSTEM.md is a symlink to ~/SANDBOX_CONTEXT.md
2. The session dir variables (PI_CODING_AGENT_SESSION_DIR, which both tools
   read, and OMP_SESSION_DIR for omp) point at <workspace>/.pi-sessions
   (.omp-sessions), and a session written there lands in the host workspace
3. The host config bundle (pi: AGENTS.md, settings.json; omp: AGENTS.md,
   config.yml, agent.db) is copied into the agent dir
4. The tool is launched without --continue, and with --continue on --resume

A recorder script stands in for the tool via [tool] binary (trusted scope). It
writes what it saw at launch to a marker file in the workspace, then stays
alive like an agent would. COI_USE_DUMMY is not set: it would replace the
launched binary.
"""

import subprocess
from pathlib import Path

import pytest

from support.helpers import (
    calculate_container_name,
    launch_recorded_tool,
    write_trusted_coi_config,
)

MARKER = ".coi-tool-session-marker"
CONTAINER_HOME = "/home/code"

SESSION_FILE = "recorder-session.jsonl"

TOOLS = {
    "pi": {
        "agent_dir": ".pi/agent",
        "session_envs": ["PI_CODING_AGENT_SESSION_DIR"],
        "files": ["AGENTS.md", "settings.json"],
    },
    "omp": {
        "agent_dir": ".omp/agent",
        "session_envs": ["PI_CODING_AGENT_SESSION_DIR", "OMP_SESSION_DIR"],
        "files": ["AGENTS.md", "config.yml", "agent.db"],
    },
}

RECORDER = """#!/bin/sh
cfg="{home}/{agent_dir}"
out="$(dirname "$0")/{marker}"
mkdir -p "$PI_CODING_AGENT_SESSION_DIR"
printf '{{}}\\n' > "$PI_CODING_AGENT_SESSION_DIR/{session_file}"
{{
    printf 'argv=%s\\n' "$*"
{env_lines}
    printf 'append_system=%s\\n' "$(readlink "$cfg/APPEND_SYSTEM.md")"
{file_lines}
}} > "$out.tmp"
mv "$out.tmp" "$out"
exec sleep 300
"""


def _recorder(spec):
    env_lines = "\n".join(f"    printf 'env:{v}=%s\\n' \"${v}\"" for v in spec["session_envs"])
    file_lines = "\n".join(
        f'    printf \'file:{f}=%s\\n\' "$(cat "$cfg/{f}")"' for f in spec["files"]
    )
    return RECORDER.format(
        home=CONTAINER_HOME,
        agent_dir=spec["agent_dir"],
        marker=MARKER,
        session_file=SESSION_FILE,
        env_lines=env_lines,
        file_lines=file_lines,
    )


def _assert_session_dir(recorded, tool_name, spec, when):
    for var in spec["session_envs"]:
        assert recorded.get(f"env:{var}") == f"/workspace/.{tool_name}-sessions", (
            f"{var} should point at the workspace{when}: {recorded}"
        )


@pytest.mark.parametrize("tool_name", sorted(TOOLS))
def test_pi_omp_session_setup(coi_binary, cleanup_containers, workspace_dir, tmp_path, tool_name):
    """
    coi shell with [tool] name = "pi" / "omp" links the sandbox context, sets the
    session dir, seeds the config bundle and passes --continue only on --resume.

    Flow:
    1. Write the host config bundle into a fake HOME
    2. Configure [tool] name and binary = the recorder script (trusted scope)
    3. coi shell --background: check the recorded launch state and that the
       session file the recorder wrote is in the host workspace
    4. coi kill the container, then coi shell --background --resume: check
       that the tool got --continue
    """
    spec = TOOLS[tool_name]
    container_name = calculate_container_name(workspace_dir, 1)

    fake_home = tmp_path / "fake_home"
    host_cfg = fake_home / spec["agent_dir"]
    host_cfg.mkdir(parents=True)
    for name in spec["files"]:
        (host_cfg / name).write_text(f"host {name} for {tool_name}")

    script = Path(workspace_dir) / "fake-agent.sh"
    script.write_text(_recorder(spec))
    script.chmod(0o755)
    marker = Path(workspace_dir) / MARKER
    session_file = Path(workspace_dir) / f".{tool_name}-sessions" / SESSION_FILE

    env = write_trusted_coi_config(
        f'[tool]\nname = "{tool_name}"\nbinary = "/workspace/fake-agent.sh"\n'
    )
    env.pop("COI_USE_DUMMY", None)
    env["HOME"] = str(fake_home)

    # === Phase 1: new session ===

    recorded = launch_recorded_tool(coi_binary, workspace_dir, env, marker)

    assert recorded.get("append_system") == f"{CONTAINER_HOME}/SANDBOX_CONTEXT.md", (
        f"~/{spec['agent_dir']}/APPEND_SYSTEM.md should link to ~/SANDBOX_CONTEXT.md: {recorded}"
    )
    _assert_session_dir(recorded, tool_name, spec, "")
    assert session_file.exists(), (
        f"a session written to PI_CODING_AGENT_SESSION_DIR is not in the workspace: {session_file}"
    )
    for name in spec["files"]:
        assert recorded.get(f"file:{name}") == f"host {name} for {tool_name}", (
            f"host {name} was not copied into ~/{spec['agent_dir']}: {recorded}"
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

    recorded = launch_recorded_tool(coi_binary, workspace_dir, env, marker, "--resume")

    assert "--continue" in recorded.get("argv", "").split(), (
        f"--resume should launch {tool_name} with --continue: {recorded}"
    )
    _assert_session_dir(recorded, tool_name, spec, " on resume")
