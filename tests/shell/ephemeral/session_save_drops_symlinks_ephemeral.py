"""
Test for coi shell - session save keeps only regular files and dirs.

The container's tool config dir is untrusted. A symlink saved verbatim under
~/.coi/sessions-claude/<id>/.claude could point anywhere on the host, so the
save drops symlinks and special files on both pull paths.

Tests that:
1. tar path (container still running on exit): symlinks and a FIFO in
   ~/.claude are not recreated in the saved session; regular files and dirs are.
2. `incus file pull` fallback (tar hidden in the container): symlinks are not
   recreated; regular files and dirs are. No FIFO here: the fallback opens a
   FIFO as a regular file, which blocks with no writer.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    exec_in,
    session_for_container,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
)

SESSIONS_DIR = Path.home() / ".coi" / "sessions-claude"

FILES_SETUP = (
    "mkdir -p ~/.claude/coi-sub && "
    "echo real > ~/.claude/coi-real.txt && "
    "echo nested > ~/.claude/coi-sub/nested.txt"
)
SYMLINKS_SETUP = (
    "ln -s coi-real.txt ~/.claude/coi-safe-link && "
    "ln -s /etc/passwd ~/.claude/coi-abs-evil && "
    "ln -s ../../../../etc/shadow ~/.claude/coi-sub/coi-esc-evil && "
    "ln -s /etc ~/.claude/coi-dir-link"
)
SYMLINKS = [
    "coi-safe-link",
    "coi-abs-evil",
    "coi-dir-link",
    os.path.join("coi-sub", "coi-esc-evil"),
]


def _drain_output(child):
    lf = child.logfile_read
    for attr in ("get_raw_output", "get_output", "get_display_stripped"):
        if hasattr(lf, attr):
            return getattr(lf, attr)()
    return ""


def _save_session(coi_binary, workspace_dir, setup):
    """Run an ephemeral shell, plant setup in ~/.claude, exit bash (container
    keeps running, so the save runs while it is up) and return (output, saved
    .claude dir or None, session dir or None)."""
    container_name = calculate_container_name(workspace_dir, 1)
    child = spawn_coi(
        coi_binary, ["shell"], cwd=workspace_dir, env={"COI_USE_DUMMY": "1"}, timeout=120
    )
    try:
        wait_for_container_ready(child, timeout=60)
        wait_for_prompt(child, timeout=90)

        child.send("exit")
        time.sleep(0.3)
        child.send("\x0d")
        time.sleep(3)

        rc, out = exec_in(coi_binary, container_name, setup, user=1000)
        assert rc == 0, f"setup in ~/.claude should succeed:\n{out}"

        child.send("exit")
        time.sleep(0.3)
        child.send("\x0d")
        try:
            child.expect(EOF, timeout=60)
        except TIMEOUT:
            pass
        output = _drain_output(child)
    finally:
        try:
            child.close(force=False)
        except Exception:
            child.close(force=True)
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )

    session_id = session_for_container(SESSIONS_DIR, container_name)
    if session_id is None:
        return output, None, None
    session_dir = SESSIONS_DIR / session_id
    return output, session_dir / ".claude", session_dir


def _assert_only_regular_saved(saved, output, dropped):
    assert saved is not None and saved.is_dir(), f"session should be saved. Output:\n{output}"
    assert (saved / "coi-real.txt").read_text() == "real\n", "regular file should be saved"
    assert (saved / "coi-sub" / "nested.txt").read_text() == "nested\n", (
        "nested regular file should be saved"
    )
    for name in dropped:
        path = saved / name
        assert not os.path.lexists(path), f"{name} should be dropped, but exists at {path}"


def test_session_save_tar_path_drops_symlinks_and_fifo(
    coi_binary, cleanup_containers, workspace_dir
):
    setup = f"{FILES_SETUP} && {SYMLINKS_SETUP} && mkfifo ~/.claude/coi-fifo"
    output, saved, session_dir = _save_session(coi_binary, workspace_dir, setup)
    try:
        assert "Fast session save unavailable" not in output, (
            f"the save should take the tar path. Output:\n{output}"
        )
        _assert_only_regular_saved(saved, output, [*SYMLINKS, "coi-fifo"])
    finally:
        if session_dir is not None:
            shutil.rmtree(session_dir, ignore_errors=True)


def test_session_save_file_pull_fallback_drops_symlinks(
    coi_binary, cleanup_containers, workspace_dir
):
    setup = f'{FILES_SETUP} && {SYMLINKS_SETUP} && sudo mv "$(command -v tar)" /usr/local/coi-tar-hidden'
    output, saved, session_dir = _save_session(coi_binary, workspace_dir, setup)
    try:
        assert "Fast session save unavailable" in output, (
            f"the save should fall back to file pull. Output:\n{output}"
        )
        _assert_only_regular_saved(saved, output, SYMLINKS)
    finally:
        if session_dir is not None:
            shutil.rmtree(session_dir, ignore_errors=True)
