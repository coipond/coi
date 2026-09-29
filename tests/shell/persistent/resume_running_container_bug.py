"""
Regression tests for issue #413: coi shell --resume=<id> when container is already Running.

After a host reboot, Incus may restore containers to their pre-reboot Running state via
stateful restore. Before the fix, running `coi shell --resume=<id>` in that situation
failed with:

  failed to setup session: slot 1 is already in use by a running container
  coi-<id>-1 - this should not happen (bug in slot allocation)

Fix (internal/session/setup.go): allow reusing a Running container when ResumeFromID is
set. The slot in the resume path comes from saved session metadata, not AllocateSlot(),
so a running container at that slot is the expected container to reconnect to.

Simulated without rebooting by:
1. Starting a persistent session (container stays Running after coi exits)
2. Modifying the saved session metadata to set persistent=false
3. Running coi shell --resume=<id> — now succeeds

See: https://github.com/mensfeld/coi/issues/413
"""

import json
import os
import subprocess
import time
from pathlib import Path

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    get_container_list,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    with_live_screen,
    write_workspace_container_config,
)

SESSIONS_DIR = Path.home() / ".coi" / "sessions-claude"


def _find_session_for_container(container_name: str) -> str | None:
    """Find the most recently modified session whose metadata matches the given container."""
    if not SESSIONS_DIR.exists():
        return None

    candidates = []
    for session_dir in SESSIONS_DIR.iterdir():
        if not session_dir.is_dir():
            continue
        metadata_file = session_dir / "metadata.json"
        if not metadata_file.exists():
            continue
        try:
            with metadata_file.open() as f:
                meta = json.load(f)
            if meta.get("container_name") == container_name:
                candidates.append((metadata_file.stat().st_mtime, session_dir.name))
        except (json.JSONDecodeError, OSError):
            continue

    if not candidates:
        return None

    candidates.sort(reverse=True)
    return candidates[0][1]


def _start_persistent_session_and_exit(coi_binary, workspace_dir, env):
    """
    Start a persistent coi shell, wait for the dummy to be ready, then exit immediately.

    Container stays Running after exit (persistent mode). Returns the child process
    output for debugging.
    """
    # Persistence is config-driven: [container] persistent = true
    write_workspace_container_config(workspace_dir, persistent=True)

    child = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    # Exit the dummy tool (no interaction needed — metadata is already saved)
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(3)

    # Exit bash — coi exits, container stays Running (persistent mode)
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")

    try:
        child.expect(EOF, timeout=30)
    except TIMEOUT:
        pass

    raw_output = ""
    if hasattr(child.logfile_read, "get_raw_output"):
        raw_output = child.logfile_read.get_raw_output()
    elif hasattr(child.logfile_read, "get_output"):
        raw_output = child.logfile_read.get_output()

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    time.sleep(2)
    return raw_output


def test_resume_running_container_succeeds(coi_binary, cleanup_containers, workspace_dir):
    """
    Regression test for bug #413: resuming a non-persistent session whose container
    is already Running (e.g. restored by Incus stateful restore after a host reboot).

    Before the fix, coi shell --resume=<id> failed with:
      "slot N is already in use by a running container — this should not happen"

    After the fix (setup.go: allow reuse when ResumeFromID is set), resume succeeds
    by reconnecting to the already-running container.

    Simulation steps:
    1. Start persistent session (via config) → container stays Running after coi exits
    2. Edit metadata: set persistent=false (simulates post-reboot non-persistent session)
    3. coi shell --resume=<id> → should succeed (reconnects to running container)
    """
    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    # ------------------------------------------------------------------ #
    # Phase 1: Start persistent session, exit immediately (no interaction) #
    # Container stays Running; metadata is saved before dummy starts.      #
    # ------------------------------------------------------------------ #

    raw_output = _start_persistent_session_and_exit(coi_binary, workspace_dir, env)

    # Verify container is still Running (persistent exit keeps it up)
    containers = get_container_list()
    assert container_name in containers, (
        f"Container {container_name} should still be Running after persistent exit. "
        f"Containers: {containers}\nOutput:\n{raw_output}"
    )

    # Find session ID from sessions directory (metadata is saved by SaveMetadataEarly
    # right after container setup, before the dummy tool starts).
    session_id = _find_session_for_container(container_name)
    assert session_id is not None, (
        f"Could not find session metadata for container {container_name} in {SESSIONS_DIR}. "
        f"Output:\n{raw_output}"
    )

    # ------------------------------------------------------------------ #
    # Phase 2: Simulate post-reboot state                                 #
    # Modify metadata: persistent=false (Incus restored non-persistent    #
    # container after reboot)                                             #
    # ------------------------------------------------------------------ #

    metadata_path = SESSIONS_DIR / session_id / "metadata.json"
    with metadata_path.open() as f:
        metadata = json.load(f)

    metadata["persistent"] = False

    with metadata_path.open("w") as f:
        json.dump(metadata, f, indent=2)

    # ------------------------------------------------------------------ #
    # Phase 3: Resume — should reuse running container (currently fails)  #
    # ------------------------------------------------------------------ #

    # Run with [shell] use_tmux = false so it runs directly (no tmux detach;
    # the --tmux flag was removed — tmux mode is config-driven).
    # The bug causes an immediate error exit; a successful resume would start
    # an interactive session that we'd then kill via timeout.
    with (Path(workspace_dir) / ".coi" / "config.toml").open("a") as f:
        f.write("\n[shell]\nuse_tmux = false\n")
    proc = subprocess.Popen(
        [coi_binary, "shell", f"--resume={session_id}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=workspace_dir,
        env={**os.environ, "COI_USE_DUMMY": "1"},
    )

    resume_stderr = ""
    resume_returncode = None
    timed_out = False

    try:
        # Send "exit\n" after a brief delay to allow setup to proceed.
        # If the bug is present, the process exits before reading stdin.
        # If setup succeeds, "exit\n" tells the dummy to quit cleanly.
        _stdout, resume_stderr = proc.communicate(input="exit\n", timeout=20)
        resume_returncode = proc.returncode
    except subprocess.TimeoutExpired:
        # Timeout means the session started and is waiting for interactive input
        # (no immediate error occurred). This is the "success" path when bug is fixed.
        proc.kill()
        proc.wait()
        timed_out = True

    if not timed_out:
        # Process exited — check it wasn't the slot conflict bug
        has_slot_conflict = (
            "slot" in resume_stderr.lower() and "already in use" in resume_stderr.lower()
        )
        assert not has_slot_conflict, (
            f"Bug #413 confirmed: resume failed with slot conflict error.\n"
            f"Stderr: {resume_stderr}\n"
            f"This should NOT happen — coi should reuse the running container.\n"
            f"See: https://github.com/mensfeld/coi/issues/413"
        )
        assert resume_returncode == 0, (
            f"Expected coi shell --resume to succeed (exit 0), got exit {resume_returncode}.\n"
            f"Stderr: {resume_stderr}"
        )
    # else: timed_out = True means setup succeeded (no immediate error) — test passes

    # ------------------------------------------------------------------ #
    # Cleanup                                                             #
    # ------------------------------------------------------------------ #

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_workaround_attach_bash_works_when_container_running(
    coi_binary, cleanup_containers, workspace_dir
):
    """
    Verify the workaround for bug #413: `coi attach <container> --bash` works
    when the container is already Running and --resume fails.

    This test should PASS even before the bug fix (workaround is functional).
    """
    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    # Start persistent session and exit immediately (container stays Running)
    _start_persistent_session_and_exit(coi_binary, workspace_dir, env)

    # Verify container is still Running
    containers = get_container_list()
    assert container_name in containers, (
        f"Container {container_name} should still be Running. Containers: {containers}"
    )

    # Workaround: coi attach --bash
    child2 = spawn_coi(
        coi_binary,
        ["attach", container_name, "--bash"],
        cwd=workspace_dir,
        env=env,
        timeout=30,
    )

    time.sleep(3)

    with with_live_screen(child2) as monitor:
        child2.send("echo WORKAROUND_OK_12345")
        time.sleep(0.3)
        child2.send("\x0d")
        time.sleep(2)
        workaround_works = wait_for_text_in_monitor(monitor, "WORKAROUND_OK_12345", timeout=15)

    assert workaround_works, (
        "Workaround 'coi attach --bash' should work when container is already Running"
    )

    child2.send("exit")
    time.sleep(0.3)
    child2.send("\x0d")

    try:
        child2.expect(EOF, timeout=10)
    except TIMEOUT:
        pass

    try:
        child2.close(force=False)
    except Exception:
        child2.close(force=True)

    # Cleanup
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
        check=False,
    )
