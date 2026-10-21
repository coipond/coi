"""
Ephemeral --resume reopens the LATEST conversation in the saved session.

One saved session can hold several Claude transcripts: `/clear` and resuming
another conversation each start a new <id>.jsonl in projects/-workspace. coi
used to resume the first file by name, so a stale or empty transcript whose
name sorted earlier won, and Claude exited with "No conversation found with
session ID".

  session 1: talk to the tool (its transcript gets a current message), then
             plant two decoys that sort first by name and have newer mtimes:
             an older conversation and a message-less stub; poweroff
  session 2 (--resume): the tool must be handed session 1's conversation,
             not either decoy.
"""

import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    get_screen_display,
    send_prompt,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_specific_container_deletion,
    wait_for_text_in_monitor,
    wait_for_text_on_screen,
    with_live_screen,
)

LATEST = "LATEST-CONVO-MARK"
STALE = "STALE-CONVO-MARK"
STALE_ID = "00000000-0000-0000-0000-000000000001"
STUB_ID = "00000000-0000-0000-0000-000000000000"

PLANT_DECOYS = (
    "D=$HOME/.claude/projects/-workspace && "
    f"""printf '%s\\n' '{{"type":"user","content":"{STALE}","timestamp":"2020-01-01T00:00:00.000Z"}}' """
    f"> $D/{STALE_ID}.jsonl && "
    f"""printf '%s\\n' '{{"type":"mode","mode":"normal"}}' > $D/{STUB_ID}.jsonl && """
    f"touch $D/{STALE_ID}.jsonl $D/{STUB_ID}.jsonl && echo DECOYS_OK_4c"
)


def _poweroff(child, container_name):
    child.send("sudo poweroff")
    time.sleep(0.3)
    child.send("\x0d")
    try:
        child.expect(EOF, timeout=60)
    except TIMEOUT:
        pass
    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)
    return wait_for_specific_container_deletion(container_name, timeout=60)


def _exit_cli_to_bash(child):
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(3)


def test_ephemeral_resume_picks_latest_conversation(coi_binary, cleanup_containers, workspace_dir):
    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: a real conversation, then two decoys that sort before it ===
    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    with with_live_screen(child) as monitor:
        time.sleep(2)
        send_prompt(child, LATEST)
        assert wait_for_text_in_monitor(monitor, f"{LATEST}-BACK", timeout=30), (
            "the tool should answer in session 1"
        )

    _exit_cli_to_bash(child)

    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send(PLANT_DECOYS)
        time.sleep(0.5)
        child.send("\x0d")
        assert wait_for_text_in_monitor(monitor, "DECOYS_OK_4c", timeout=20), (
            "planting the decoy transcripts should succeed"
        )

    assert _poweroff(child, container_name), f"container {container_name} should be deleted"

    # === Phase 2: --resume must reopen session 1's conversation ===
    child2 = spawn_coi(coi_binary, ["shell", "--resume"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child2, timeout=60)
    try:
        wait_for_text_on_screen(child2, "Resuming session", timeout=60)
        resumed = True
    except TimeoutError:
        resumed = False
    try:
        wait_for_text_on_screen(child2, LATEST, timeout=20)
        got_latest = True
    except TimeoutError:
        got_latest = False
    screen = get_screen_display(child2)

    # Clean up before asserting so a failure never leaks the container.
    _exit_cli_to_bash(child2)
    _poweroff(child2, container_name)

    assert resumed, f"the tool should be started in resume mode. Screen:\n{screen}"
    assert STUB_ID not in screen and STALE_ID not in screen, (
        f"--resume picked a decoy transcript instead of the latest conversation. Screen:\n{screen}"
    )
    assert STALE not in screen, f"the stale conversation was resumed. Screen:\n{screen}"
    assert got_latest, (
        f"the resumed conversation should be session 1's ({LATEST}). Screen:\n{screen}"
    )
