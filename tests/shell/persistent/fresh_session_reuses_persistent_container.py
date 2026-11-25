"""
#708 mechanism: a fresh `coi shell` (no --resume) reuses the SAME stopped
persistent container instead of forking a new slot.

This is what makes "switch tools on the same container via profiles" work — two
profiles that share [container] session_name (or just the same workspace, as
here) land on the same box. Without this, re-entering with a different tool would
spin up a second container. Existing tests cover stopped-container reuse via
--resume (resume_reuses_stopped_container) and the delete-then-fresh case
(new_not_resumed); this covers the NO-resume reuse path (FindReusablePersistentSlot).
"""

import subprocess
import time

from support.helpers import (
    calculate_container_name,
    exit_tool_to_bash,
    get_container_list,
    poweroff_session,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    write_workspace_container_config,
)


def _exit_and_poweroff(child):
    assert exit_tool_to_bash(child), "the tool should exit to bash"
    poweroff_session(child)


def test_fresh_session_reuses_stopped_persistent_container(
    coi_binary, cleanup_containers, workspace_dir
):
    env = {"COI_USE_DUMMY": "1"}
    write_workspace_container_config(workspace_dir, persistent=True)
    slot1 = calculate_container_name(workspace_dir, 1)
    slot2 = calculate_container_name(workspace_dir, 2)

    # === Phase 1: create the persistent container, then stop+keep it ===
    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)
    _exit_and_poweroff(child)
    time.sleep(3)

    # === Phase 2: fresh `coi shell` (NO --resume) must reuse the stopped box ===
    child2 = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child2, timeout=60)
    wait_for_prompt(child2, timeout=90)

    output = ""
    if hasattr(child2.logfile_read, "get_raw_output"):
        output = child2.logfile_read.get_raw_output()

    containers = get_container_list()

    _exit_and_poweroff(child2)
    time.sleep(3)
    for name in (slot1, slot2):
        subprocess.run(
            [coi_binary, "container", "delete", name, "--force"],
            capture_output=True,
            timeout=30,
        )

    # Primary, output-independent signal: no second (slot-2) container was forked
    # — a fork would leave slot-2 running alongside the stopped slot-1.
    assert slot2 not in containers, (
        f"a second container ({slot2}) was forked instead of reusing {slot1}: {containers}"
    )
    # Corroborating: coi announced the reuse on stderr.
    assert "Reusing stopped persistent container" in output, (
        f"fresh session should reuse the stopped persistent container, not fork.\n{output}"
    )
