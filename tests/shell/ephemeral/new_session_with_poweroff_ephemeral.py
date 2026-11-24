"""
Test for coi shell - ephemeral session with shutdown.

Tests the complete lifecycle:
1. Start dummy in ephemeral mode
2. Send a message and verify response
3. Exit to bash shell
4. Issue sudo shutdown 0
5. Verify proper cleanup messages from coi
6. Verify container is removed
"""

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
    wait_for_specific_container_deletion,
    wait_for_text_in_monitor,
    with_live_screen,
)


def test_ephemeral_session_with_shutdown(coi_binary, cleanup_containers, workspace_dir):
    """
    Test ephemeral session lifecycle with sudo shutdown 0.

    Flow:
    1. Start coi shell (ephemeral mode)
    2. Interact with dummy
    3. Exit claude to get to bash
    4. Run sudo shutdown 0 to stop container
    5. Verify cleanup messages appear
    6. Verify container is deleted
    """
    env = {"COI_USE_DUMMY": "1"}

    # Launch ephemeral container
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

    # Step 1: Interact with dummy to verify it works
    with with_live_screen(child) as monitor:
        time.sleep(2)
        send_prompt(child, "hello from test")
        responded = wait_for_text_in_monitor(monitor, "hello from test-BACK", timeout=30)
        assert responded, "Dummy CLI should respond with echo"

    # Step 2: Exit claude to get to bash shell
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(2)

    # Wait for bash prompt to be ready
    time.sleep(3)

    # Verify we're in bash using arithmetic (result won't match input)
    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send("echo $((12345+54321))")
        time.sleep(0.5)
        child.send("\x0d")
        time.sleep(2)
        # 12345 + 54321 = 66666
        in_bash = wait_for_text_in_monitor(monitor, "66666", timeout=20)
        assert in_bash, "Should be in bash shell after exiting claude"

    # Verify container is running before shutdown
    containers = get_container_list()
    assert container_name in containers, f"Container {container_name} should be running"

    # Step 3: Issue sudo poweroff (more immediate than shutdown 0)
    child.send("sudo poweroff")
    time.sleep(0.3)
    child.send("\x0d")

    # Step 4: Wait for process to exit
    try:
        child.expect(EOF, timeout=60)
    except TIMEOUT:
        pass

    # Get output for verification
    output = child_output(child)

    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    # Step 5: Wait for container to be deleted (60s to account for network teardown)
    container_deleted = wait_for_specific_container_deletion(container_name, timeout=60)

    # Step 6: Verify cleanup messages
    assert "Saving session data" in output or "Session data saved" in output, (
        f"Should see session save message. Got:\n{output}"
    )

    assert "Container was stopped" in output or "removing" in output.lower(), (
        f"Should see container removal message. Got:\n{output}"
    )

    # Step 7: Verify container was deleted
    assert container_deleted, (
        f"Container {container_name} should be deleted after poweroff (waited 60s)"
    )
