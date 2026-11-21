"""
Test for coi shell - a tool binary installed by `[tool] pre_launch` starts.

Tests that:
1. The not-installed check runs after `[tool] pre_launch`: a `[tool] binary`
   absent from the image but created by a pre_launch command starts normally.
2. coi's not-installed hint does not appear in the pane.

Flow:
- a stand-in agent in the workspace records its start
- trusted config: `[tool] binary` in /tmp (not in the image), and a pre_launch
  command that installs the stand-in there
- coi shell --background (tmux), COI_USE_DUMMY unset so argv[0] stays the binary
- wait for the agent's marker in the workspace, then read the pane
"""

import time
from pathlib import Path

from support.helpers import (
    calculate_container_name,
    start_background_shell,
    tmux_as_code_user,
    write_trusted_coi_config,
)

BINARY = "/tmp/coi-late-agent"
MARKER = ".coi-late-agent-started"

FAKE_AGENT = f"""#!/bin/sh
echo started > /workspace/{MARKER}
exec sleep 300
"""


def test_tool_missing_binary_pre_launch(coi_binary, cleanup_containers, workspace_dir):
    """A binary that pre_launch installs passes the check and the tool starts."""
    script = Path(workspace_dir) / "late-agent.sh"
    script.write_text(FAKE_AGENT)
    script.chmod(0o755)
    env = write_trusted_coi_config(
        f'[tool]\nbinary = "{BINARY}"\n'
        f'pre_launch = ["install -m 755 /workspace/late-agent.sh {BINARY}"]\n'
    )
    env.pop("COI_USE_DUMMY", None)
    start_background_shell(coi_binary, workspace_dir, env, slot=1, debug=False, timeout=180)

    marker = Path(workspace_dir) / MARKER
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(1)
    assert marker.exists(), "the tool installed by pre_launch should start"

    container_name = calculate_container_name(workspace_dir, 1)
    pane = tmux_as_code_user(
        coi_binary, container_name, "capture-pane", "-p", "-J", "-t", f"coi-{container_name}"
    )
    assert "not found in this container" not in pane, (
        f"coi's not-installed hint should not appear:\n{pane}"
    )
