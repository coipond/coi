"""
Test that coi shell with [tool] name = "goose" sets up the goose session.

Tests that:
1. goose is launched as `goose session`, and after an ephemeral recreate with
   --resume as `goose session --resume --session-id <id>`, where <id> is the
   session whose working_dir is exactly the workspace (not a subdir's)
2. GOOSE_MODE=auto is in the tool env with the default permission_mode
   (bypass)
3. The host ~/.config/goose (config.yaml, .goosehints) is copied in, and the
   container's .goosehints holds both the user's text and coi's managed block
4. ~/.local/share/goose is a mount of the host tool-data dir

A recorder script stands in for goose via [tool] binary (trusted scope). On
`session list ...` (coi's session discovery) it prints two sessions, the
subdir's first, so taking the first row would pick the wrong one. Otherwise it
writes what it saw at launch to a marker file in the workspace, then stays
alive like an agent would. COI_USE_DUMMY is not set: it would replace the
launched binary and skip the discovery.
"""

import subprocess
from pathlib import Path

from support.helpers import (
    calculate_container_name,
    launch_recorded_tool,
    tool_data_dir,
    write_trusted_coi_config,
)

MARKER = ".coi-tool-session-marker"
HINTS_COPY = ".coi-goosehints-copy"
PROBE = "coi-mount-probe"
CONTAINER_HOME = "/home/code"

SESSIONS = (
    '[{"id":"20261107_2","working_dir":"/workspace/sub"},'
    '{"id":"20261107_1","working_dir":"/workspace"}]'
)

RECORDER = f"""#!/bin/sh
if [ "$1" = session ] && [ "$2" = list ]; then
    printf '%s\\n' '{SESSIONS}'
    exit 0
fi
cfg="{CONTAINER_HOME}/.config/goose"
dir="$(dirname "$0")"
echo probe > "{CONTAINER_HOME}/.local/share/goose/{PROBE}"
cat "$cfg/.goosehints" > "$dir/{HINTS_COPY}" 2>/dev/null
{{
    printf 'argv=%s\\n' "$*"
    printf 'goose_mode=%s\\n' "$GOOSE_MODE"
    printf 'config=%s\\n' "$(tr -d '\\n' < "$cfg/config.yaml")"
}} > "$dir/{MARKER}.tmp"
mv "$dir/{MARKER}.tmp" "$dir/{MARKER}"
exec sleep 300
"""


def test_goose_session_setup(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    coi shell with [tool] name = "goose" launches `goose session`, sets
    GOOSE_MODE, seeds ~/.config/goose with the managed hints block, mounts the
    data dir from the host and resumes the workspace's own session by id.

    Flow:
    1. Write host ~/.config/goose (config.yaml, .goosehints) into a fake HOME
    2. Configure [tool] name and binary = the recorder script (trusted scope)
    3. coi shell --background: check argv, GOOSE_MODE, config, hints and the
       probe file in the host tool-data dir
    4. coi kill the container, then coi shell --background --resume: check
       that goose got --resume --session-id 20261107_1
    """
    container_name = calculate_container_name(workspace_dir, 1)

    fake_home = tmp_path / "fake_home"
    host_cfg = fake_home / ".config" / "goose"
    host_cfg.mkdir(parents=True)
    (host_cfg / "config.yaml").write_text("GOOSE_PROVIDER: coi-test\n")
    (host_cfg / ".goosehints").write_text("host hints for goose\n")

    script = Path(workspace_dir) / "fake-agent.sh"
    script.write_text(RECORDER)
    script.chmod(0o755)
    marker = Path(workspace_dir) / MARKER

    env = write_trusted_coi_config('[tool]\nname = "goose"\nbinary = "/workspace/fake-agent.sh"\n')
    env.pop("COI_USE_DUMMY", None)
    env["HOME"] = str(fake_home)

    # === Phase 1: new session ===

    recorded = launch_recorded_tool(coi_binary, workspace_dir, env, marker)

    assert recorded.get("argv") == "session", (
        f"a new session must start `goose session`: {recorded}"
    )
    assert recorded.get("goose_mode") == "auto", (
        f"the default permission_mode (bypass) should set GOOSE_MODE=auto: {recorded}"
    )
    assert recorded.get("config") == "GOOSE_PROVIDER: coi-test", (
        f"host config.yaml was not copied into ~/.config/goose: {recorded}"
    )

    hints = (Path(workspace_dir) / HINTS_COPY).read_text()
    assert "host hints for goose" in hints, f"the user's .goosehints text is missing:\n{hints}"
    assert "# BEGIN COI Sandbox Context" in hints and "# END COI Sandbox Context" in hints, (
        f"coi's managed block is missing from .goosehints:\n{hints}"
    )

    share = tool_data_dir(workspace_dir, "goose", "share").relative_to(Path.home())
    probe = fake_home / share / PROBE
    assert probe.is_file(), (
        f"{CONTAINER_HOME}/.local/share/goose is not a mount of the host tool-data dir (no {probe})"
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

    assert recorded.get("argv") == "session --resume --session-id 20261107_1", (
        f"--resume should resume the workspace's own session by id: {recorded}"
    )
    assert recorded.get("goose_mode") == "auto", f"GOOSE_MODE should be auto on resume: {recorded}"
