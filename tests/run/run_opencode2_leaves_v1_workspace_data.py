"""
Test for coi run - opencode2 leaves OpenCode v1 data in the workspace to opencode.

coi up to 0.15 kept opencode's data in the workspace
(<workspace>/.local/{share,state}/opencode); coi moves it to the host tool-data
dir the first time the tool runs. That data is always v1's, so only opencode
takes it: with opencode2 first, v2 would open v1's DB and opencode would start
with no sessions.

Tests that:
1. An opencode2 run on such a workspace sees none of the v1 data
2. The v1 data stays in the workspace, and opencode2's host dirs don't get it
3. A later opencode run moves the data to its own host dir and sees it
"""

import os
import shutil
import subprocess
from pathlib import Path

from support.helpers import tool_data_dir

PROBE = (
    'echo "SHARE=$(ls -A ~/.local/share/opencode | tr "\\n" " ")"; '
    'echo "STATE=$(ls -A ~/.local/state/opencode | tr "\\n" " ")"; '
    "cat ~/.local/share/opencode/opencode.db 2>/dev/null || true"
)


def _run(coi_binary, workspace_dir, cfg, command):
    env = os.environ.copy()
    env["COI_CONFIG"] = str(cfg)
    env.pop("COI_USE_DUMMY", None)
    return subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=240,
        stdin=subprocess.DEVNULL,
        env=env,
    )


def _value(lines, key):
    for line in lines:
        if line.startswith(key + "="):
            return line[len(key) + 1 :].split()
    return None


def test_opencode2_leaves_v1_workspace_data_to_opencode(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    old_share = Path(workspace_dir) / ".local" / "share" / "opencode"
    old_state = Path(workspace_dir) / ".local" / "state" / "opencode"
    old_share.mkdir(parents=True)
    old_state.mkdir(parents=True)
    (old_share / "opencode.db").write_text("v1-db\n")
    (old_state / "prompt-history.jsonl").write_text("{}\n")

    cfg_v2 = tmp_path / "opencode2.toml"
    cfg_v2.write_text('[tool]\nname = "opencode2"\n')
    cfg_v1 = tmp_path / "opencode.toml"
    cfg_v1.write_text('[tool]\nname = "opencode"\n')
    try:
        # === Phase 1: opencode2 runs first and sees none of v1's data ===
        first = _run(coi_binary, workspace_dir, cfg_v2, PROBE)
        output = first.stdout + first.stderr
        assert first.returncode == 0, f"opencode2 run failed:\n{output}"
        lines = first.stdout.splitlines()
        assert _value(lines, "SHARE") == [], f"opencode2 sees v1's share dir:\n{output}"
        assert _value(lines, "STATE") == [], f"opencode2 sees v1's state dir:\n{output}"
        assert "v1-db" not in lines, output

        assert (old_share / "opencode.db").read_text() == "v1-db\n", (
            f"v1's DB should stay in the workspace for opencode:\n{output}"
        )
        assert (old_state / "prompt-history.jsonl").exists(), output
        assert not (tool_data_dir(workspace_dir, "opencode2", "share") / "opencode.db").exists()
        assert not (
            tool_data_dir(workspace_dir, "opencode2", "state") / "prompt-history.jsonl"
        ).exists()

        # === Phase 2: opencode takes the data and sees it ===
        second = _run(coi_binary, workspace_dir, cfg_v1, PROBE)
        output = second.stdout + second.stderr
        assert second.returncode == 0, f"opencode run failed:\n{output}"
        lines = second.stdout.splitlines()
        assert "v1-db" in lines, f"opencode should see v1's DB:\n{output}"
        assert "prompt-history.jsonl" in (_value(lines, "STATE") or []), output

        share = tool_data_dir(workspace_dir, "opencode", "share")
        assert (share / "opencode.db").read_text() == "v1-db\n", output
        assert not (Path(workspace_dir) / ".local").exists(), (
            f"the moved data should leave nothing in the workspace:\n{output}"
        )
    finally:
        for tool in ("opencode", "opencode2"):
            shutil.rmtree(tool_data_dir(workspace_dir, tool, "share").parent, ignore_errors=True)
