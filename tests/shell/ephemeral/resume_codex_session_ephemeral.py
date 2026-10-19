"""
Test that `coi shell --resume` resumes the right codex session.

codex stores sessions as ~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl.
On resume coi reads the saved ~/.codex and launches `codex resume <uuid>` for
the lexicographically greatest rollout path, which is the newest session, not
the newest by mtime: the save does not keep mtimes. With no rollout file coi
falls back to `codex resume --last`.

`[tool] binary` points at a script in the workspace that records its argv into
a marker file and exits, so the pane drops to bash. COI_USE_DUMMY is off: it
would replace the binary. The rollout files are created in the container with
`incus exec`, and `sudo poweroff` saves the session. The test then makes the
older rollout the newest by mtime in the saved host copy, which is what discovery
reads.
"""

import json
import os
import subprocess
import time
from pathlib import Path

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    make_workspace_writable,
    spawn_coi,
    wait_for_container_ready,
    wait_for_specific_container_deletion,
    write_trusted_coi_config,
)

MARKER = ".coi-codex-argv-marker"

FAKE_CODEX = f"""#!/bin/sh
# Stand-in for codex: record how coi launched us, then exit to bash.
printf '%s\\n' "$@" > "$(dirname "$0")/{MARKER}"
"""

OLD_UUID = "11111111-1111-4111-8111-111111111111"
NEW_UUID = "22222222-2222-4222-8222-222222222222"

SESSIONS_DIR = "/home/code/.codex/sessions"

ROLLOUTS = (
    f"2026/02/01/rollout-2026-02-01T09-00-00-{NEW_UUID}.jsonl",
    f"2026/01/05/rollout-2026-01-05T10-00-00-{OLD_UUID}.jsonl",
)


def _container_exec(container_name, command):
    result = subprocess.run(
        ["incus", "exec", container_name, "--", "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"incus exec {command!r} failed: {result.stderr}"


def _saved_session_dirs(workspace_dir):
    """Return the saved codex session dirs on the host for this workspace."""
    workspace = os.path.abspath(workspace_dir)
    dirs = []
    for metadata in (Path.home() / ".coi" / "sessions-codex").glob("*/metadata.json"):
        if json.loads(metadata.read_text()).get("workspace") in (
            workspace,
            os.path.realpath(workspace),
        ):
            dirs.append(metadata.parent)
    return dirs


def _make_old_rollout_newest_by_mtime(workspace_dir):
    """In the saved host copy, give the older rollout path the newer mtime."""
    session_dirs = _saved_session_dirs(workspace_dir)
    assert session_dirs, f"no saved codex session for {workspace_dir}"
    now = time.time()
    for session_dir in session_dirs:
        new_path, old_path = (session_dir / ".codex" / "sessions" / r for r in ROLLOUTS)
        assert new_path.exists() and old_path.exists(), (
            f"the rollout files were not saved to {session_dir}"
        )
        os.utime(new_path, (now - 3600, now - 3600))
        os.utime(old_path, (now, now))


def _launch(coi_binary, workspace_dir, env, args, marker):
    """Start `coi shell` and return (child, argv the fake codex was started with)."""
    marker.unlink(missing_ok=True)
    child = spawn_coi(coi_binary, ["shell", *args], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)

    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(1)
    assert marker.exists(), f"the fake codex was not launched by coi shell {args}"
    return child, marker.read_text().split("\n")[:-1]


def _poweroff(child, coi_binary, container_name):
    """Power off from the bash pane, which saves the session, and wait for removal."""
    time.sleep(3)
    child.send("sudo poweroff")
    time.sleep(0.3)
    child.send("\x0d")
    try:
        child.expect(EOF, timeout=60)
    except TIMEOUT:
        pass
    output = child.logfile_read.get_raw_output() if child.logfile_read else ""
    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    if not wait_for_specific_container_deletion(container_name, timeout=60):
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
    return output


def test_resume_codex_session_discovery(coi_binary, cleanup_containers, workspace_dir):
    """
    --resume launches `codex resume <newest uuid>` from the saved rollout files,
    and `codex resume --last` when the saved state has none.

    Flow:
    1. Start a session with the fake codex; assert a fresh launch (no resume)
    2. Create two rollout files; poweroff (saves the session)
    3. In the saved host copy, make the older rollout the newest by mtime
    4. coi shell --resume; assert argv starts with `resume <newest-path uuid>`
    5. Remove the rollout files; poweroff (saves the session again)
    6. coi shell --resume; assert argv starts with `resume --last`
    """
    make_workspace_writable(workspace_dir)
    container_name = calculate_container_name(workspace_dir, 1)

    script = Path(workspace_dir) / "fake-codex.sh"
    script.write_text(FAKE_CODEX)
    script.chmod(0o755)
    marker = Path(workspace_dir) / MARKER

    env = write_trusted_coi_config('[tool]\nname = "codex"\nbinary = "/workspace/fake-codex.sh"\n')
    env["COI_USE_DUMMY"] = "0"

    # === Phase 1: Fresh session with rollout files ===

    child, argv = _launch(coi_binary, workspace_dir, env, [], marker)
    assert "resume" not in argv, f"a fresh launch must not resume: {argv}"

    _container_exec(
        container_name,
        " && ".join(
            f"mkdir -p {SESSIONS_DIR}/{Path(r).parent} && echo '{{}}' > {SESSIONS_DIR}/{r}"
            for r in ROLLOUTS
        ),
    )
    output = _poweroff(child, coi_binary, container_name)
    assert "Saving session data" in output, f"session should be saved. Got:\n{output}"
    _make_old_rollout_newest_by_mtime(workspace_dir)

    # === Phase 2: Resume picks the newest rollout by path, not by mtime ===

    child, argv = _launch(coi_binary, workspace_dir, env, ["--resume"], marker)
    assert argv[:2] == ["resume", NEW_UUID], (
        f"--resume should launch `codex resume {NEW_UUID}` (newest path, not mtime): {argv}"
    )

    _container_exec(container_name, f"rm -rf {SESSIONS_DIR}")
    _poweroff(child, coi_binary, container_name)

    # === Phase 3: No rollout files falls back to --last ===

    child, argv = _launch(coi_binary, workspace_dir, env, ["--resume"], marker)
    assert argv[:2] == ["resume", "--last"], (
        f"--resume without rollout files should launch `codex resume --last`: {argv}"
    )
    _poweroff(child, coi_binary, container_name)
