"""
Test for coi shell (ephemeral) - a guest shutdown that OUTLASTS the graceful
window must be force-stopped and removed, not relabeled "kept running".

Stock systemd gives service stops a 90s budget (DefaultTimeoutStopSec) while
Coi's [container] shutdown_timeout defaults to 60s, so "detected shutdown
outlives the wait" is reachable with completely ordinary units. When that
happens the cleanup must escalate exactly like `coi shutdown` does after its
graceful window — force the stop and honor the ephemeral contract (delete) —
instead of relapsing into the "Container kept running - use 'coi attach'"
mislabel it was built to fix.

This test makes the overrun cheap: shutdown_timeout is pinned to 5s and a
transient unit holds the guest in "stopping" for ~30s.
"""

import time
from pathlib import Path

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    get_container_list,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_specific_container_deletion,
    wait_for_text_in_monitor,
    with_live_screen,
)


def test_slow_shutdown_exceeding_timeout_is_forced(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Pin [container] shutdown_timeout = 5 in the workspace config
    2. Start coi shell (ephemeral), exit the dummy tool to bash
    3. Install a transient unit whose ExecStop sleeps ~30s, poweroff non-forced
    4. Cleanup detects the shutdown, waits 5s, must FORCE the stop
    5. The ephemeral container must be removed; no "kept running" mislabel
    """
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(exist_ok=True)
    (coi_dir / "config.toml").write_text("[container]\nshutdown_timeout = 5\n")

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

    # Verify we actually reached bash before typing power commands into it.
    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send("echo $((12345+54321))")
        time.sleep(0.5)
        child.send("\x0d")
        in_bash = wait_for_text_in_monitor(monitor, "66666", timeout=20)
        assert in_bash, "Should be in bash shell after exiting the dummy tool"

    # Slow-stop unit: the (non-forced) shutdown stays in "stopping" ~30s,
    # far past the 5s graceful window configured above.
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

    assert container_name in get_container_list(), (
        f"Container {container_name} should be running before poweroff"
    )

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

    if hasattr(child.logfile_read, "get_raw_output"):
        output = child.logfile_read.get_raw_output()
    elif hasattr(child.logfile_read, "get_output"):
        output = child.logfile_read.get_output()
    else:
        output = ""

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    deleted = wait_for_specific_container_deletion(container_name, timeout=90)

    assert "forcing the stop" in output, (
        f"a shutdown outlasting the graceful window must be escalated to a force stop. "
        f"Got:\n{output}"
    )
    assert "Container kept running" not in output, (
        f"a detected shutdown must never relapse into the 'kept running' mislabel. Got:\n{output}"
    )
    assert deleted, (
        f"Ephemeral container {container_name} must be removed after the forced stop "
        f"(waited 90s). Output:\n{output}"
    )
