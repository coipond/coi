"""
Integration tests for #929: opencode's data dirs live outside the workspace.

opencode keeps a snapshot git repo in its XDG data dir whose work tree is the
workspace. coi used to point XDG_DATA_HOME at <workspace>/.local/share, so each
snapshot re-added the snapshot repo itself: .local grew by GBs and git pegged
the CPU. coi now mounts per-workspace host dirs over ~/.local/share/opencode
and ~/.local/state/opencode instead, and moves data an older coi left in the
workspace.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from support.helpers import calculate_container_name, tool_data_dir

# Prints what the tests check, one fact per line, and writes a file through
# each mount so the host side can be checked too.
PROBE = (
    'echo "XDG_DATA_HOME=${XDG_DATA_HOME:-unset}"; '
    'echo "XDG_STATE_HOME=${XDG_STATE_HOME:-unset}"; '
    "stat -c 'owner %U %n' ~/.local/share ~/.local/state "
    "~/.local/share/opencode ~/.local/state/opencode; "
    "cat ~/.local/share/opencode/migrated.txt 2>/dev/null; "
    "echo from-container > ~/.local/share/opencode/written.txt; "
    "echo from-container > ~/.local/state/opencode/written.txt"
)


def _write_cfg(path, tool, persistent=False):
    body = ""
    if persistent:
        body += "[container]\npersistent = true\n\n"
    body += f'[tool]\nname = "{tool}"\n'
    path.write_text(body)


def _run(coi_binary, workspace_dir, cfg, slot, command):
    env = os.environ.copy()
    env["COI_CONFIG"] = str(cfg)
    env.pop("COI_USE_DUMMY", None)
    return subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--slot",
            str(slot),
            "--",
            "sh",
            "-c",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=240,
        stdin=subprocess.DEVNULL,
        env=env,
    )


def _assert_probe(result, workspace_dir):
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"probe run failed. output:\n{output}"
    lines = result.stdout.splitlines()

    # The XDG redirect into the workspace is gone; opencode uses its defaults.
    assert "XDG_DATA_HOME=unset" in lines, output
    assert "XDG_STATE_HOME=unset" in lines, output

    # The mounts and their parents belong to the code user: a root-owned
    # ~/.local/state (left by Incus creating a mount target) would break every
    # other tool that writes there.
    for path in (
        "/home/code/.local/share",
        "/home/code/.local/state",
        "/home/code/.local/share/opencode",
        "/home/code/.local/state/opencode",
    ):
        assert f"owner code {path}" in lines, f"{path} should be owned by code. output:\n{output}"

    share = tool_data_dir(workspace_dir, "opencode", "share")
    state = tool_data_dir(workspace_dir, "opencode", "state")
    assert (share / "written.txt").read_text().strip() == "from-container", output
    assert (state / "written.txt").read_text().strip() == "from-container", output
    assert not (Path(workspace_dir) / ".local").exists(), (
        f"nothing opencode-related may be left in the workspace. output:\n{output}"
    )
    return lines


def test_opencode_data_mounted_and_migrated(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """A workspace an older coi left opencode data in: the data moves to the
    host tool-data dir, the empty .local/ is pruned, and the container sees
    the moved data at opencode's default XDG paths."""
    old_share = Path(workspace_dir) / ".local" / "share" / "opencode"
    old_state = Path(workspace_dir) / ".local" / "state" / "opencode"
    old_share.mkdir(parents=True)
    old_state.mkdir(parents=True)
    (old_share / "migrated.txt").write_text("old-session-db\n")
    (old_state / "prompt-history.jsonl").write_text("{}\n")

    cfg = tmp_path / "cfg.toml"
    _write_cfg(cfg, "opencode")
    try:
        result = _run(coi_binary, workspace_dir, cfg, 1, PROBE)
        lines = _assert_probe(result, workspace_dir)
        assert "old-session-db" in lines, (
            f"migrated data should be visible in the container. output:\n{result.stdout}{result.stderr}"
        )
        state = tool_data_dir(workspace_dir, "opencode", "state")
        assert (state / "prompt-history.jsonl").exists(), "state dir should be migrated too"
    finally:
        shutil.rmtree(tool_data_dir(workspace_dir, "opencode", "share").parent, ignore_errors=True)


def test_opencode_data_mount_added_to_reused_container(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """A persistent container created without the mounts (another tool, or an
    older coi) gets them on its next reuse with opencode, instead of opencode
    silently starting over in the container's own home. Another tool's data
    mount on the same path (opencode2 shares ~/.local/share/opencode) is
    replaced: two disk devices on one path would stop the container starting."""
    slot = 4
    container_name = calculate_container_name(workspace_dir, slot)
    cfg_claude = tmp_path / "claude.toml"
    cfg_opencode = tmp_path / "opencode.toml"
    _write_cfg(cfg_claude, "claude", persistent=True)
    _write_cfg(cfg_opencode, "opencode", persistent=True)
    other_tool_dir = tmp_path / "opencode2-share"
    other_tool_dir.mkdir()

    def devices():
        return subprocess.run(
            ["incus", "config", "device", "list", container_name],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.split()

    try:
        first = _run(coi_binary, workspace_dir, cfg_claude, slot, "true")
        assert first.returncode == 0, f"first run failed:\n{first.stdout}{first.stderr}"
        assert not any(d.startswith("tool-data-opencode") for d in devices()), devices()

        # The stopped container as another tool sharing the path would leave it.
        add = subprocess.run(
            [
                "incus",
                "config",
                "device",
                "add",
                container_name,
                "tool-data-opencode2-share",
                "disk",
                f"source={other_tool_dir}",
                "path=/home/code/.local/share/opencode",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert add.returncode == 0, add.stderr

        second = _run(coi_binary, workspace_dir, cfg_opencode, slot, PROBE)
        _assert_probe(second, workspace_dir)
        attached = devices()
        assert "tool-data-opencode2-share" not in attached, attached
        assert "tool-data-opencode-share" in attached, attached
        assert "tool-data-opencode-state" in attached, attached
    finally:
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=60,
        )
        shutil.rmtree(tool_data_dir(workspace_dir, "opencode", "share").parent, ignore_errors=True)


FAKE_SERVER = Path(__file__).resolve().parent.parent / "support" / "fake_openai.py"

# Real opencode against a fake OpenAI-compatible model served inside the
# container: no token, no network. Each `<binary> run` is a full agent step,
# which takes snapshots of the work tree. Then report where the snapshot repo
# lives and whether it tracked the workspace and/or opencode's own files.
# v1 and v2 use the same data dir; v2's run also starts a background
# `serve --service`, which inherits the /dev/null redirects.
SNAPSHOT_PROBE = (
    "python3 /workspace/.fake-openai.py 18080 > /tmp/fake-openai.log 2>&1 & sleep 2; "
    "for i in 1 2 3; do "
    'timeout 90 {binary} run "say ok $i" </dev/null >/dev/null 2>&1 || echo "RUN_FAILED $i rc=$?"; '
    "done; "
    "G=$(dirname \"$(find ~/.local/share/opencode/snapshot -name HEAD -not -path '*/logs/*' | head -1)\"); "
    'echo "SNAPSHOT=$G"; '
    'echo "TRACKED=$(git --git-dir "$G" --work-tree /workspace ls-files | grep -c a.txt)"; '
    'echo "SELF=$(git --git-dir "$G" --work-tree /workspace ls-files | grep -c opencode/)"; '
    "echo \"REQUESTS=$(grep -c 'POST /v1/chat/completions' /tmp/fake-openai.log)\""
)

OPENCODE_FAKE_CONFIG = {
    "model": "fake/fake",
    "snapshot": True,
    "provider": {
        "fake": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "Fake",
            "options": {"baseURL": "http://127.0.0.1:18080/v1", "apiKey": "x"},
            "models": {"fake": {"name": "fake"}},
        }
    },
}


def _value(lines, key):
    for line in lines:
        if line.startswith(key + "="):
            return line[len(key) + 1 :]
    return None


# The tool name is also its binary and its tool-data dir name.
@pytest.mark.parametrize("tool", ["opencode", "opencode2"])
def test_opencode_snapshots_do_not_track_their_own_data(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, tool
):
    """The #929 regression itself, for OpenCode v1 and v2. With the data dir
    inside the workspace the snapshot repo re-added its own objects every step
    (~800 of its own files after the second prompt, 200M after eight). Its data
    must live outside the work tree: the snapshots still track the workspace,
    but none of opencode's files, and nothing appears in the workspace."""
    ws = Path(workspace_dir)
    subprocess.run(["git", "init", "-q"], cwd=ws, check=True)
    (ws / "a.txt").write_text("hello\n")
    subprocess.run(["git", "add", "a.txt"], cwd=ws, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"],
        cwd=ws,
        check=True,
    )
    shutil.copy(FAKE_SERVER, ws / ".fake-openai.py")

    cfg = tmp_path / "cfg.toml"
    cfg.write_text(
        f'[tool]\nname = "{tool}"\n\n'
        "[defaults.environment]\n"
        f"OPENCODE_CONFIG_CONTENT = '{json.dumps(OPENCODE_FAKE_CONFIG)}'\n"
    )
    try:
        result = _run(coi_binary, workspace_dir, cfg, 1, SNAPSHOT_PROBE.format(binary=tool))
        output = result.stdout + result.stderr
        lines = result.stdout.splitlines()
        assert result.returncode == 0, f"probe failed. output:\n{output}"
        assert not any(line.startswith("RUN_FAILED") for line in lines), output
        # Not vacuous: opencode really talked to the model and took snapshots
        # of the workspace.
        assert int(_value(lines, "REQUESTS") or 0) >= 3, output
        snapshot = _value(lines, "SNAPSHOT") or ""
        assert snapshot.startswith("/home/code/.local/share/opencode/snapshot/"), output
        assert int(_value(lines, "TRACKED") or 0) >= 1, (
            f"the snapshot should track the workspace's files. output:\n{output}"
        )
        assert _value(lines, "SELF") == "0", (
            f"the snapshot repo tracked opencode's own data (#929). output:\n{output}"
        )
        assert not (ws / ".local").exists(), output
        assert (tool_data_dir(workspace_dir, tool, "share") / "snapshot").is_dir(), (
            f"the snapshot repo should persist in the host tool-data dir. output:\n{output}"
        )
    finally:
        shutil.rmtree(tool_data_dir(workspace_dir, tool, "share").parent, ignore_errors=True)
