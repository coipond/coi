"""
Test for coi shell (ephemeral) - a SLOW guest shutdown must still end with
the container removed.

Cleanup distinguishes "user powered the container off" (delete it) from
"user typed exit" (keep it for re-attach) by polling the container state for
a fixed ~5s after the shell ends. Any shutdown slower than that window was
mislabeled as a normal exit: cleanup printed "Container kept running - use
'coi attach' to reconnect..." and the ephemeral container was never removed
(it finished stopping moments later and lingered as a stopped leftover).

The stock power wrappers (`close`/`poweroff`/...) use `systemctl --force
poweroff`, which skips unit stop jobs and usually finishes inside the old
window — which is exactly why the plain poweroff tests never caught this.
This test pins the guest in "stopping" deterministically: a transient unit
with a slow ExecStop plus a NON-forced `systemctl poweroff` (which honors
unit stops) keeps the container shutting down for ~30s.
"""

import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    child_output,
    get_container_list,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_specific_container_deletion,
    wait_for_text_in_monitor,
    with_live_screen,
)


def test_slow_shutdown_removes_ephemeral(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Start coi shell (ephemeral), exit the dummy tool to bash
    2. Install a transient unit whose ExecStop sleeps 30s
    3. Power off WITHOUT --force so the slow unit stop is honored
    4. The shell dies early in the shutdown; the guest keeps stopping ~30s
    5. Cleanup must still recognize the poweroff and DELETE the container
    """
    env = {"COI_USE_DUMMY": "1"}

    child = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    container_name = calculate_container_name(workspace_dir, 1)

    # Exit the dummy tool to bash
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(3)

    # Verify we actually reached bash before typing power commands into it:
    # a slow dummy exit would otherwise swallow the command and the failure
    # would masquerade as a shutdown-detection bug.
    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send("echo $((12345+54321))")
        time.sleep(0.5)
        child.send("\x0d")
        in_bash = wait_for_text_in_monitor(monitor, "66666", timeout=20)
        assert in_bash, "Should be in bash shell after exiting the dummy tool"

    # A transient unit whose stop takes ~30s: this holds the whole (non-forced)
    # shutdown in "stopping" well past cleanup's old fixed polling window.
    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send(
            "sudo systemd-run --unit=coi-test-slowstop -p TimeoutStopSec=45 "
            "-p ExecStop='/bin/sleep 30' /bin/sleep infinity && echo SLOWSTOP_READY"
        )
        time.sleep(0.5)
        child.send("\x0d")
        started = wait_for_text_in_monitor(monitor, "SLOWSTOP_READY", timeout=20)
        assert started, "transient slow-stop unit should start"

    # Verify container is running before shutdown
    assert container_name in get_container_list(), (
        f"Container {container_name} should be running before poweroff"
    )

    # Non-forced poweroff honors the slow unit stop (the wrappers' --force
    # would skip it and stop too fast to reproduce the race)
    child.send("sudo systemctl poweroff")
    time.sleep(0.3)
    child.send("\x0d")
    # Leave the shell right away so the coi process regains control (EOF) at
    # the START of the guest shutdown. With a non-forced poweroff the exec
    # session otherwise survives deep into the shutdown and cleanup would
    # find the container already stopped — no in-flight window to test.
    time.sleep(1)
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")

    try:
        child.expect(EOF, timeout=90)
    except TIMEOUT:
        pass

    output = child_output(child)

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    # The user powered the container off: however slow the guest shutdown is,
    # the ephemeral container must be recognized as stopped and removed.
    deleted = wait_for_specific_container_deletion(container_name, timeout=120)

    assert "Container is shutting down, waiting" in output, (
        f"cleanup must detect the in-flight shutdown (the guest is pinned in "
        f"'stopping' when EOF arrives). Got:\n{output}"
    )
    assert "Container kept running" not in output, (
        f"a slow poweroff must not be mislabeled as a normal exit. Got:\n{output}"
    )
    assert deleted, (
        f"Ephemeral container {container_name} must be removed after a slow poweroff "
        f"(waited 120s). Output:\n{output}"
    )
