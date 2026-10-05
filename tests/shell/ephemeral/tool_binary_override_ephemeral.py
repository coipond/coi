"""
Test that `[tool] binary` replaces the executable coi launches for the tool.

The setting is documented as "Binary name to execute. Defaults to the tool name
if not set." (schema/defs/ToolConfig.json), so with `binary` pointing at a
script, `coi shell` must run that script — with the tool's usual arguments —
instead of the stock `claude` executable.

The script lives in the workspace (bind-mounted into the container) and records
the arguments it was started with into a marker file, then stays alive like an
agent would. COI_USE_DUMMY is deliberately NOT set: it swaps argv[0] for the
dummy stub and would mask whether `binary` is honored.

The config is supplied in TRUSTED scope (COI_CONFIG) — the realistic place for a
path to a wrapper — so the result can't be confused with untrusted-config
handling.
"""

import subprocess
import time
from pathlib import Path

from support.helpers import calculate_container_name, write_trusted_coi_config

MARKER = ".coi-binary-override-marker"

FAKE_AGENT = f"""#!/bin/sh
# Stand-in for the agent CLI: record how coi launched us, then stay alive.
printf '%s\\n' "$@" > "$(dirname "$0")/{MARKER}"
exec sleep 300
"""


def _container_processes(container_name):
    """Return the container's process list (for the failure message)."""
    result = subprocess.run(
        ["incus", "exec", container_name, "--", "ps", "-eo", "pid,args"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout if result.returncode == 0 else f"(ps failed: {result.stderr})"


def test_tool_binary_override_is_launched(coi_binary, cleanup_containers, workspace_dir):
    """
    With `[tool] binary` set, coi shell launches that executable with the tool's
    arguments.

    Flow:
    1. Write a fake agent script into the workspace
    2. Configure `[tool] binary` to its in-container path (trusted scope)
    3. Start `coi shell --background` without COI_USE_DUMMY
    4. Wait for the script's marker file; assert it exists and received the
       tool's arguments (claude's launch flags)
    """
    container_name = calculate_container_name(workspace_dir, 1)

    script = Path(workspace_dir) / "fake-agent.sh"
    script.write_text(FAKE_AGENT)
    script.chmod(0o755)
    marker = Path(workspace_dir) / MARKER

    env = write_trusted_coi_config('[tool]\nbinary = "/workspace/fake-agent.sh"\n')
    env.pop("COI_USE_DUMMY", None)

    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"

    # The tool starts inside tmux shortly after the container is ready.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(1)

    processes = _container_processes(container_name) if not marker.exists() else ""
    assert marker.exists(), (
        "[tool] binary was not launched: coi ran the default tool executable "
        "instead of the configured /workspace/fake-agent.sh.\n"
        f"Processes in the container:\n{processes}"
    )

    args = marker.read_text().split("\n")
    assert "--verbose" in args, (
        f"the configured binary should receive the tool's launch arguments, got: {args}"
    )
