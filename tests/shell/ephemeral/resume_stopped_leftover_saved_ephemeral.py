"""
Test for coi shell --resume - a stopped leftover container is saved before it is deleted.

After a host reboot or a killed coi, an ephemeral session's container is left
Stopped and holds the session's newest tool config. --resume used to delete it
and restore the older saved copy.

Tests that:
- --resume saves the stopped leftover's session data before deleting it
- the resumed container gets the newest content, not the older saved copy

Flow:
  session 1: write OLD into the tool config dir, poweroff (saved on the host)
  session 2 (--resume): overwrite it with NEW, kill coi (SIGKILL) and
             `incus stop --force` the container, so it is left Stopped unsaved
  session 3 (--resume): the file must hold NEW
"""

import os
import signal
import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    child_output,
    incus_status,
    poweroff_and_wait,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    with_live_screen,
)

OLD = "COI_LEFTOVER_OLD_3c1e"
NEW = "COI_LEFTOVER_NEW_8d2b"
SENTINEL_PATH = "$HOME/.claude/coi-leftover-sentinel.txt"


def _exit_cli_to_bash(child):
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")


def _run_in_bash(child, command, marker, timeout=60):
    """Run an idempotent command in the shell's bash pane until it prints
    marker. The typed line splits marker with "" so its echo never matches,
    and resending covers a tool that has not exited to bash yet."""
    typed = f'{command} && echo {marker[:-2]}""{marker[-2:]}'
    deadline = time.monotonic() + timeout
    with with_live_screen(child) as monitor:
        while time.monotonic() < deadline:
            child.send(typed)
            time.sleep(0.5)
            child.send("\x0d")
            if wait_for_text_in_monitor(monitor, marker, timeout=5):
                return True
    return False


def _start_shell(coi_binary, workspace_dir, env, args):
    child = spawn_coi(coi_binary, ["shell", *args], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)
    _exit_cli_to_bash(child)
    return child


def _wait_for_status(container_name, status, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if incus_status(container_name) == status:
            return True
        time.sleep(1)
    return False


def test_resume_saves_stopped_leftover(coi_binary, cleanup_containers, workspace_dir):
    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    # === Session 1: save OLD on the host ===
    child = _start_shell(coi_binary, workspace_dir, env, [])
    assert _run_in_bash(
        child,
        f"mkdir -p $HOME/.claude && echo {OLD} > {SENTINEL_PATH}",
        "WROTE_OLD_5e",
    ), "writing OLD inside the container should complete"
    assert poweroff_and_wait(child, coi_binary, container_name), (
        f"container {container_name} should be deleted after poweroff"
    )

    # === Session 2: write NEW, then leave the container Stopped and unsaved ===
    child2 = _start_shell(coi_binary, workspace_dir, env, ["--resume"])
    assert _run_in_bash(child2, f"echo {NEW} > {SENTINEL_PATH}", "WROTE_NEW_7a"), (
        "writing NEW inside the container should complete"
    )
    os.kill(child2.pid, signal.SIGKILL)
    try:
        child2.expect(EOF, timeout=30)
    except TIMEOUT:
        pass
    child2.close(force=True)
    subprocess.run(
        ["incus", "stop", container_name, "--force"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert _wait_for_status(container_name, "STOPPED"), (
        f"container {container_name} should be left Stopped, got {incus_status(container_name)!r}"
    )

    # === Session 3: the stopped leftover is saved, then resumed from ===
    child3 = _start_shell(coi_binary, workspace_dir, env, ["--resume"])
    got_new = _run_in_bash(child3, f"grep -qx {NEW} {SENTINEL_PATH}", "HAS_NEW_2f")
    out3 = child_output(child3)
    poweroff_and_wait(child3, coi_binary, container_name)

    assert "saving its session data first" in out3, (
        f"--resume should save the stopped leftover before deleting it. Got:\n{out3}"
    )
    assert got_new, (
        "the resumed container must hold NEW from the stopped leftover, "
        "not OLD from the older saved copy"
    )
