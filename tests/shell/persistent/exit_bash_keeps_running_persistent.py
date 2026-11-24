"""
Test for coi shell in persistent mode - exit bash keeps container running.

Tests the behavior:
1. Start dummy in persistent mode
2. Exit claude to bash
3. Exit bash (not poweroff)
4. Verify container is still running
5. Verify can attach with coi attach --bash
6. Cleanup: kill the container

Expected:
- Exiting bash (not poweroff) keeps container running
- coi attach --bash works to reconnect
- Container can be killed for cleanup
"""

import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    child_output,
    get_container_list,
    send_prompt,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    with_live_screen,
    write_workspace_container_config,
)


def test_persistent_exit_bash_keeps_container_running(
    coi_binary, cleanup_containers, workspace_dir
):
    """
    Test that exiting bash (not poweroff) keeps persistent container running.

    Flow:
    1. Start coi shell in persistent mode (via workspace config)
    2. Interact with dummy
    3. Exit claude to get to bash
    4. Exit bash (should keep container running)
    5. Verify container is still running
    6. Attach with coi attach --bash
    7. Verify we can interact
    8. Kill container for cleanup
    """
    env = {"COI_USE_DUMMY": "1"}

    # Persistence is config-driven: [container] persistent = true
    write_workspace_container_config(workspace_dir, persistent=True)

    # === Phase 1: Start persistent session and exit normally ===

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

    # Interact with dummy
    with with_live_screen(child) as monitor:
        time.sleep(2)
        send_prompt(child, "test message")
        responded = wait_for_text_in_monitor(monitor, "test message-BACK", timeout=30)
        assert responded, "Dummy CLI should respond"

    # Exit CLI to bash
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(2)

    # Wait for bash prompt to be ready
    time.sleep(3)

    # Verify we're in bash
    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send("echo $((99+1))")
        time.sleep(0.5)
        child.send("\x0d")
        time.sleep(2)
        in_bash = wait_for_text_in_monitor(monitor, "100", timeout=20)
        assert in_bash, "Should be in bash shell"

    # Exit bash (not poweroff) - container should stay running
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")

    # Wait for coi shell to exit
    try:
        child.expect(EOF, timeout=30)
    except TIMEOUT:
        pass

    # Get output for verification
    output1 = child_output(child)

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    # === Phase 2: Verify container is still running ===

    time.sleep(2)
    containers = get_container_list()
    assert container_name in containers, (
        f"Container {container_name} should still be running after exit. Output was:\n{output1}"
    )

    # Verify output mentions container kept running
    assert "Container kept running" in output1 or "coi attach" in output1.lower(), (
        f"Should mention container kept running. Got:\n{output1}"
    )

    # === Phase 3: Attach with --bash ===

    child2 = spawn_coi(
        coi_binary,
        ["attach", container_name, "--bash"],
        cwd=workspace_dir,
        env=env,
        timeout=30,
    )

    # Wait a moment for bash prompt
    time.sleep(3)

    # Verify we can interact in bash
    with with_live_screen(child2) as monitor:
        child2.send("echo attached-successfully")
        time.sleep(0.3)
        child2.send("\x0d")
        time.sleep(1)
        attached = wait_for_text_in_monitor(monitor, "attached-successfully", timeout=10)
        assert attached, "Should be able to interact after attaching"

    # Exit the attached session
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

    # === Phase 4: Cleanup - kill the container ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )

    # Verify container is gone
    time.sleep(1)
    containers = get_container_list()
    assert container_name not in containers, (
        f"Container {container_name} should be deleted after cleanup"
    )
