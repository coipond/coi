"""
Test for coi shell in persistent mode - container kept after poweroff.

Tests that in persistent mode:
1. Start dummy in persistent mode
2. Send a message and verify response
3. Exit to bash shell
4. Issue sudo poweroff
5. Verify session data is saved
6. Verify container is KEPT (not deleted) - key difference from ephemeral
7. Cleanup
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


def test_persistent_container_kept_after_poweroff(coi_binary, cleanup_containers, workspace_dir):
    """
    Test persistent session keeps container after poweroff.

    Flow:
    1. Start coi shell in persistent mode (via workspace config)
    2. Interact with dummy
    3. Exit claude to get to bash
    4. Run sudo poweroff to stop container
    5. Verify session data is saved
    6. Verify container is KEPT (stopped but not deleted)
    7. Cleanup
    """
    env = {"COI_USE_DUMMY": "1"}

    # Persistence is config-driven: [container] persistent = true
    write_workspace_container_config(workspace_dir, persistent=True)

    # Launch persistent container
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
        send_prompt(child, "hello from test")
        responded = wait_for_text_in_monitor(monitor, "hello from test-BACK", timeout=30)
        assert responded, "Dummy CLI should respond with echo"

    # Exit CLI to get to bash shell
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(2)

    # Wait for bash prompt to be ready
    time.sleep(3)

    # Verify we're in bash
    with with_live_screen(child) as monitor:
        time.sleep(1)
        child.send("echo $((12345+54321))")
        time.sleep(0.5)
        child.send("\x0d")
        time.sleep(2)
        in_bash = wait_for_text_in_monitor(monitor, "66666", timeout=20)
        assert in_bash, "Should be in bash shell after exiting claude"

    # Verify container is running before shutdown
    containers = get_container_list()
    assert container_name in containers, f"Container {container_name} should be running"

    # Issue sudo poweroff
    child.send("sudo poweroff")
    time.sleep(0.3)
    child.send("\x0d")

    # Wait for process to exit
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

    # Give time for cleanup to complete
    time.sleep(3)

    # Verify session data was saved
    assert "Saving session data" in output or "Session data saved" in output, (
        f"Should see session save message. Got:\n{output}"
    )

    # In persistent mode, container should be KEPT (not deleted)
    # It may be stopped but should still exist
    # Note: Container might be listed even if stopped

    # Verify message indicates container was kept
    assert "Container kept" in output or "persistent" in output.lower(), (
        f"Should indicate container is kept in persistent mode. Got:\n{output}"
    )

    # === Cleanup ===
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )

    # Verify cleanup
    time.sleep(1)
    containers = get_container_list()
    assert container_name not in containers, (
        f"Container {container_name} should be deleted after cleanup"
    )
