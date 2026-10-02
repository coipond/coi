"""
Test `[tool] pre_launch`: commands that run inside the container before the
tool starts in `coi shell` (issue #852, e.g. `claude update`).

The tool is replaced (via `[tool] binary`) by a stand-in agent that records
whether the pre-launch marker already existed when it started, so ordering is
observable. COI_USE_DUMMY is deliberately NOT set: it would replace argv[0]
and mask the configured binary.

Verifies that:
1. pre_launch commands from trusted config run BEFORE the tool, in order;
   a failing command doesn't stop the remaining commands or the tool;
2. pre_launch from a project's .coi/config.toml (untrusted) is ignored with a
   warning, and the tool still starts.
"""

import subprocess
import time
from pathlib import Path

from support.helpers import write_trusted_coi_config

AGENT_MARKER = ".coi-agent-started"
PRE_MARKER = ".coi-pre-launch-ran"

FAKE_AGENT = f"""#!/bin/sh
# Stand-in for the agent CLI: record whether pre-launch ran first, then stay alive.
dir="$(dirname "$0")"
if [ -e "$dir/{PRE_MARKER}" ]; then echo "pre-launch-before-agent" > "$dir/{AGENT_MARKER}"
else echo "no-pre-launch" > "$dir/{AGENT_MARKER}"; fi
exec sleep 300
"""


def _write_fake_agent(workspace_dir):
    script = Path(workspace_dir) / "fake-agent.sh"
    script.write_text(FAKE_AGENT)
    script.chmod(0o755)


def _start_shell(coi_binary, workspace_dir, env):
    env.pop("COI_USE_DUMMY", None)
    return subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )


def _wait_for(path, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not path.exists():
        time.sleep(1)
    return path.exists()


def test_pre_launch_runs_before_tool(coi_binary, cleanup_containers, workspace_dir):
    """Trusted pre_launch: runs first and in order; a failing command doesn't
    block the rest or the tool."""
    _write_fake_agent(workspace_dir)
    env = write_trusted_coi_config(
        "[tool]\n"
        'binary = "/workspace/fake-agent.sh"\n'
        f'pre_launch = ["exit 3", "echo ran > /workspace/{PRE_MARKER}"]\n'
    )

    result = _start_shell(coi_binary, workspace_dir, env)
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"

    agent = Path(workspace_dir) / AGENT_MARKER
    assert _wait_for(agent), "the tool never started after the pre-launch commands"
    assert (Path(workspace_dir) / PRE_MARKER).exists(), (
        "the second pre_launch command should run even though the first failed"
    )
    assert agent.read_text().strip() == "pre-launch-before-agent", (
        "pre_launch must finish before the tool starts"
    )


def test_pre_launch_ignored_from_project_config(coi_binary, cleanup_containers, workspace_dir):
    """Untrusted pre_launch (a repo's .coi/config.toml) is ignored with a warning;
    the tool still starts."""
    _write_fake_agent(workspace_dir)
    project_cfg = Path(workspace_dir) / ".coi" / "config.toml"
    project_cfg.parent.mkdir(exist_ok=True)
    project_cfg.write_text(f'[tool]\npre_launch = ["echo ran > /workspace/{PRE_MARKER}"]\n')
    env = write_trusted_coi_config('[tool]\nbinary = "/workspace/fake-agent.sh"\n')

    result = _start_shell(coi_binary, workspace_dir, env)
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
    assert "ignoring 'tool.pre_launch' in project config" in result.stderr, (
        f"expected a warning about the ignored project pre_launch:\n{result.stderr}"
    )

    agent = Path(workspace_dir) / AGENT_MARKER
    assert _wait_for(agent), "the tool should start normally"
    assert not (Path(workspace_dir) / PRE_MARKER).exists(), (
        "pre_launch from a project's config must not run"
    )
    assert agent.read_text().strip() == "no-pre-launch"
