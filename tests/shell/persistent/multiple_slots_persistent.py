"""
Test for coi shell in persistent mode - multiple slots running in parallel with isolation.

Tests that:
1. Start persistent session on slot 1, create marker file in ~/
2. Detach (exit bash, container keeps running)
3. Start persistent session on slot 2
4. Verify both containers run independently in parallel
5. Create marker file in slot 2's ~/, verify slot 1's file is NOT visible (isolation)
6. Cleanup both containers
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


def test_persistent_multiple_slots_parallel(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that multiple persistent slots can run in parallel with isolated home directories.

    Flow:
    1. Start coi shell in persistent mode (slot 1 auto-allocated)
    2. Interact with dummy, create marker file in ~/
    3. Exit claude, exit bash (detach - container stays running)
    4. Start coi shell again (slot 2 auto-allocated)
    5. Verify both containers are running
    6. Create marker file in slot 2, verify slot 1's file is NOT visible (isolation)
    7. Cleanup both containers
    """
    env = {"COI_USE_DUMMY": "1"}

    # Persistence is config-driven: [container] persistent = true
    write_workspace_container_config(workspace_dir, persistent=True)

    container_name_1 = calculate_container_name(workspace_dir, 1)
    container_name_2 = calculate_container_name(workspace_dir, 2)

    # === Phase 1: Start persistent session on slot 1 ===

    child1 = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child1, timeout=60)
    wait_for_prompt(child1, timeout=90)

    # Verify slot 1 container exists
    containers = get_container_list()
    assert container_name_1 in containers, (
        f"Container {container_name_1} should exist after starting slot 1"
    )

    # Interact with dummy on slot 1
    with with_live_screen(child1) as monitor:
        time.sleep(2)
        send_prompt(child1, "slot 1 message")
        responded = wait_for_text_in_monitor(monitor, "slot 1 message-BACK", timeout=30)
        assert responded, "Fake claude on slot 1 should respond"

    # Exit CLI to bash to create marker file
    child1.send("exit")
    time.sleep(0.3)
    child1.send("\x0d")
    time.sleep(2)

    # Wait for bash prompt to be ready
    time.sleep(3)

    # Create a unique marker file in slot 1's home directory
    with with_live_screen(child1) as monitor:
        child1.send("echo 'slot1-secret-data' > ~/slot1_marker.txt")
        time.sleep(0.5)
        child1.send("\x0d")
        time.sleep(2)
        child1.send("cat ~/slot1_marker.txt")
        time.sleep(0.5)
        child1.send("\x0d")
        created = wait_for_text_in_monitor(monitor, "slot1-secret-data", timeout=20)
        assert created, "Should create marker file in slot 1"

    # === Phase 2: Detach from slot 1 (exit bash, container stays running) ===

    # Exit bash (detach - container stays running)
    child1.send("exit")
    time.sleep(0.3)
    child1.send("\x0d")

    try:
        child1.expect(EOF, timeout=30)
    except TIMEOUT:
        pass

    # Get output for debugging
    output1 = child_output(child1)

    try:
        child1.close(force=False)
    except Exception:
        child1.close(force=True)

    # Verify slot 1 container is still running
    time.sleep(5)
    containers = get_container_list()
    assert container_name_1 in containers, (
        f"Container {container_name_1} should still be running after detach. Output:\n{output1}"
    )

    # === Phase 3: Start persistent session on slot 2 ===

    child2 = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=120,
    )

    wait_for_container_ready(child2, timeout=60)
    wait_for_prompt(child2, timeout=90)

    # === Phase 4: Verify both containers are running ===

    containers = get_container_list()
    assert container_name_1 in containers, (
        f"Container {container_name_1} (slot 1) should still be running"
    )
    assert container_name_2 in containers, (
        f"Container {container_name_2} (slot 2) should be running"
    )

    # Interact with dummy on slot 2
    with with_live_screen(child2) as monitor:
        time.sleep(2)
        send_prompt(child2, "slot 2 message")
        responded = wait_for_text_in_monitor(monitor, "slot 2 message-BACK", timeout=30)
        assert responded, "Fake claude on slot 2 should respond"

    # Exit CLI to bash to test isolation
    child2.send("exit")
    time.sleep(0.3)
    child2.send("\x0d")
    time.sleep(2)

    # Wait for bash prompt to be ready
    time.sleep(3)

    # === Phase 5: Verify home directory isolation ===

    # Create a marker file in slot 2's home directory
    with with_live_screen(child2) as monitor:
        child2.send("echo 'slot2-secret-data' > ~/slot2_marker.txt")
        time.sleep(0.5)
        child2.send("\x0d")
        time.sleep(2)
        child2.send("cat ~/slot2_marker.txt")
        time.sleep(0.5)
        child2.send("\x0d")
        created = wait_for_text_in_monitor(monitor, "slot2-secret-data", timeout=20)
        assert created, "Should create marker file in slot 2"

    # Verify slot 2 CANNOT see slot 1's marker file (isolation check)
    with with_live_screen(child2) as monitor:
        child2.send("cat ~/slot1_marker.txt 2>&1 || echo 'FILE_NOT_FOUND'")
        time.sleep(0.5)
        child2.send("\x0d")
        time.sleep(2)
        # Should NOT find slot1's file - expect "No such file" or our marker
        isolated = wait_for_text_in_monitor(
            monitor, "FILE_NOT_FOUND", timeout=20
        ) or wait_for_text_in_monitor(monitor, "No such file", timeout=2)
        assert isolated, (
            "Slot 2 should NOT see slot 1's home directory files (isolation violation!)"
        )

    # Verify slot 2 does NOT contain slot 1's secret data
    with with_live_screen(child2) as monitor:
        child2.send("grep -r 'slot1-secret-data' ~/ 2>/dev/null || echo 'ISOLATION_OK'")
        time.sleep(0.5)
        child2.send("\x0d")
        time.sleep(2)
        no_leak = wait_for_text_in_monitor(monitor, "ISOLATION_OK", timeout=20)
        assert no_leak, "Slot 1's data should not leak to slot 2's home directory"

    # Close child2 (already in bash, just exit)
    child2.send("exit")
    time.sleep(0.3)
    child2.send("\x0d")

    try:
        child2.expect(EOF, timeout=30)
    except TIMEOUT:
        pass

    try:
        child2.close(force=False)
    except Exception:
        child2.close(force=True)

    # === Phase 6: Cleanup both containers ===

    # Force delete both containers
    subprocess.run(
        [coi_binary, "container", "delete", container_name_1, "--force"],
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        [coi_binary, "container", "delete", container_name_2, "--force"],
        capture_output=True,
        timeout=30,
    )

    # Verify both containers are gone
    time.sleep(1)
    containers = get_container_list()
    assert container_name_1 not in containers, (
        f"Container {container_name_1} should be deleted after cleanup"
    )
    assert container_name_2 not in containers, (
        f"Container {container_name_2} should be deleted after cleanup"
    )
