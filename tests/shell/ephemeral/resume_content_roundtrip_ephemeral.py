"""
Ephemeral --resume actually round-trips the tool config directory's CONTENT.

The existing resume tests only assert the log strings ("Session data saved" /
"Resuming session") — the dummy prints "Resuming session" merely from being handed
a session ID, so a broken saveSessionData/restoreSessionData (PushDirectory /
Chown) would still pass. This test proves the real save→restore:

  session 1: write a sentinel file into the tool config dir ($HOME/.claude), then
             poweroff (ephemeral: container deleted, config dir pulled to the host)
  session 2 (--resume): the sentinel must be present in the FRESH container with
             identical content and owned code:code (restoreSessionData pushes it
             back and chowns it).

If the round-trip is broken the sentinel is absent after resume and this fails red.
"""

import time

from support.helpers import (
    calculate_container_name,
    poweroff_and_wait,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    with_live_screen,
)

# Distinct from the file PATH echoed on the command line, so a screen match means
# `cat` actually printed the file content (not the command echo).
SENTINEL = "COI_RESUME_ROUNDTRIP_SENTINEL_7a3f"
SENTINEL_PATH = "$HOME/.claude/coi-resume-sentinel.txt"


def _exit_cli_to_bash(child):
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(3)


def _drain_output(child):
    """Best-effort capture of everything the child emitted (screen or raw)."""
    lf = child.logfile_read
    for attr in ("get_raw_output", "get_output", "get_display_stripped"):
        if hasattr(lf, attr):
            return getattr(lf, attr)()
    return ""


def test_ephemeral_resume_restores_session_content(coi_binary, cleanup_containers, workspace_dir):
    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: write a sentinel into the tool config dir, then poweroff ===
    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    _exit_cli_to_bash(child)

    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send(
            f"mkdir -p $HOME/.claude && echo {SENTINEL} > {SENTINEL_PATH} && echo WROTE_OK_9f"
        )
        time.sleep(0.5)
        child.send("\x0d")
        assert wait_for_text_in_monitor(monitor, "WROTE_OK_9f", timeout=20), (
            "the sentinel write inside the container should complete"
        )

    deleted = poweroff_and_wait(child, coi_binary, container_name)
    out1 = _drain_output(child)
    assert deleted, f"container {container_name} should be deleted after poweroff"
    # Localize a later round-trip failure to save-vs-restore: the SAVE must happen
    # in session 1 (this is exactly what the pre-existing tests already assert).
    assert "Session data saved" in out1 or "Saving session data" in out1, (
        f"session data should have been saved on poweroff. Got:\n{out1}"
    )

    # === Phase 2: resume — the sentinel must be restored with code:code ownership ===
    child2 = spawn_coi(coi_binary, ["shell", "--resume"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child2, timeout=60)
    wait_for_prompt(child2, timeout=90)

    _exit_cli_to_bash(child2)

    got_sentinel = False
    got_owner = False
    with with_live_screen(child2) as monitor:
        time.sleep(1)
        child2.send(f"cat {SENTINEL_PATH}; echo OWNER=$(stat -c '%U:%G' {SENTINEL_PATH})")
        time.sleep(0.5)
        child2.send("\x0d")
        got_sentinel = wait_for_text_in_monitor(monitor, SENTINEL, timeout=20)
        got_owner = wait_for_text_in_monitor(monitor, "OWNER=code:code", timeout=20)

    # Clean up the second (resumed) container before asserting, so a failed
    # assertion never leaks it.
    container_name2 = calculate_container_name(workspace_dir, 1)
    poweroff_and_wait(child2, coi_binary, container_name2)

    assert got_sentinel, (
        "the sentinel written in session 1 must be restored into the resumed "
        "container — ephemeral --resume did not round-trip the tool config content"
    )
    assert got_owner, "the restored config file must be owned code:code (restoreSessionData chown)"
