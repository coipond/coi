"""
Test for coi shell - a configured tool missing from the container.

Tests that:
1. With a `[tool] binary` that is not in the container, the tmux pane shows
   coi's hint naming the binary, the tool and [container.build] agents.
2. bash's own "command not found" does not appear in the pane.

Flow:
- trusted config sets `[tool] binary` to a path that does not exist
- coi shell --background (tmux), COI_USE_DUMMY unset so argv[0] stays the binary
- read the session's pane with tmux capture-pane
"""

import time

from support.helpers import (
    calculate_container_name,
    start_background_shell,
    tmux_as_code_user,
    write_trusted_coi_config,
)

MISSING = "/workspace/no-such-agent"
HINT = f"coi: {MISSING} not found in this container."


def test_tool_missing_binary_hint(coi_binary, cleanup_containers, workspace_dir):
    """The launch guard prints coi's hint instead of bash's error."""
    env = write_trusted_coi_config(f'[tool]\nbinary = "{MISSING}"\n')
    env.pop("COI_USE_DUMMY", None)
    start_background_shell(coi_binary, workspace_dir, env, slot=1, debug=False, timeout=180)

    container_name = calculate_container_name(workspace_dir, 1)
    target = f"coi-{container_name}"
    deadline = time.monotonic() + 60
    pane = ""
    while time.monotonic() < deadline:
        pane = tmux_as_code_user(
            coi_binary, container_name, "capture-pane", "-p", "-J", "-t", target
        )
        if HINT in pane:
            break
        time.sleep(1)

    assert HINT in pane, f"expected coi's not-installed hint in the pane:\n{pane}"
    assert (
        "If claude is missing from the image, add it to [container.build] agents, "
        "run coi build --force"
    ) in pane, f"the hint should name the tool and the fix:\n{pane}"
    assert "command not found" not in pane, f"bash's own error should not appear:\n{pane}"
