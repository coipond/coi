"""
Test for coi shell in persistent mode - `close` stops the container and
cleanup reports it truthfully.

`close` is the in-container wrapper for `systemctl --force poweroff`: it
shuts the guest DOWN. In persistent mode the container must be KEPT but end
up STOPPED — and the cleanup message must say so. The persistent cleanup
branch used to print "Container kept running - use 'coi attach' to
reconnect..." unconditionally whenever the container existed, i.e. also
while `close` was powering it off, telling the user their instance was still
up when it was going (or already) down.
"""

import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    incus_status,
    send_prompt,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    with_live_screen,
    write_workspace_container_config,
)


def test_close_stops_and_keeps_persistent(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Start coi shell in persistent mode (via workspace config)
    2. Exit the dummy tool to bash
    3. Run `close` (the poweroff wrapper users are told about)
    4. Verify the container is KEPT but reaches STOPPED
    5. Verify cleanup does NOT claim the container was kept running
    """
    env = {"COI_USE_DUMMY": "1"}
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

    container_name = calculate_container_name(workspace_dir, 1)

    with with_live_screen(child) as monitor:
        time.sleep(2)
        send_prompt(child, "hello from close test")
        responded = wait_for_text_in_monitor(monitor, "hello from close test-BACK", timeout=30)
        assert responded, "Dummy CLI should respond with echo"

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

    # Power the container off with the `close` wrapper
    child.send("close")
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

    # The container must be KEPT (persistent) and reach STOPPED: close
    # invokes a poweroff, so "still running" is never the end state.
    status = ""
    deadline = time.time() + 60
    while time.time() < deadline:
        status = incus_status(container_name)
        if status.lower() == "stopped":
            break
        time.sleep(1)

    assert status != "", f"Persistent container {container_name} must be kept after close"
    assert status.lower() == "stopped", (
        f"close powers the container off; expected STOPPED, got {status}"
    )

    # The cleanup message must reflect that: claiming the container was
    # "kept running" (and suggesting `coi attach`) after a poweroff is the
    # bug this test pins down.
    assert "Container kept running" not in output, (
        f"cleanup must not claim a powering-off container was kept running. Got:\n{output}"
    )
    assert "kept" in output.lower(), (
        f"cleanup should still say the persistent container was kept. Got:\n{output}"
    )
