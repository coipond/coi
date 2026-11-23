"""
Test for coi persist - a persisted session survives poweroff and the next coi shell.

Tests that:
1. An ephemeral `coi shell` persisted from outside with `coi persist`
   is kept (stopped) after `sudo poweroff` inside the session
2. The session's cleanup does not remove it
3. A plain `coi shell` (no --slot, no persistent config) restarts that
   container instead of allocating a fresh slot, and the files are still there
"""

import os
import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    child_output,
    exec_in,
    incus_status,
    spawn_coi,
    start_background_shell,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    with_live_screen,
)


def test_persist_survives_poweroff_and_next_shell(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. coi shell (ephemeral), write a marker file
    2. coi persist <container> from outside
    3. Exit the dummy to bash, sudo poweroff
    4. Container still exists (stopped)
    5. coi shell --background without --slot reuses it; the marker is there
    """
    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)
    marker = "/home/code/persist_marker.txt"

    child = spawn_coi(coi_binary, ["shell", "--workspace", workspace_dir], env=env, timeout=120)
    wait_for_container_ready(child, timeout=90)
    wait_for_prompt(child, timeout=90)

    rc, out = exec_in(coi_binary, container_name, f"echo kept > {marker}")
    assert rc == 0, f"marker write failed: {out}"

    result = subprocess.run(
        [coi_binary, "persist", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"persist should succeed. stderr: {result.stderr}"

    # Exit the dummy to the bash pane.
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    with with_live_screen(child) as monitor:
        deadline = time.monotonic() + 30
        in_bash = False
        while time.monotonic() < deadline and not in_bash:
            child.send("echo $((12345+54321))")
            time.sleep(0.3)
            child.send("\x0d")
            in_bash = wait_for_text_in_monitor(monitor, "66666", timeout=5)
        assert in_bash, "should be in bash after exiting the dummy"

    child.send("sudo poweroff")
    time.sleep(0.3)
    child.send("\x0d")
    try:
        child.expect(EOF, timeout=120)
    except TIMEOUT:
        pass
    output = child_output(child)
    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)

    assert "Container was stopped, removing" not in output, (
        f"persisted container removed:\n{output}"
    )
    assert "Container kept (stopped)" in output, f"want the kept (stopped) message:\n{output}"
    assert incus_status(container_name) == "STOPPED", (
        f"persisted container should exist stopped, got {incus_status(container_name)!r}"
    )

    # A plain coi shell restarts it instead of forking slot 2.
    name, result = start_background_shell(
        coi_binary, workspace_dir, {**os.environ, "COI_USE_DUMMY": "1"}
    )
    launch_output = result.stdout + result.stderr
    assert name == container_name, f"want {container_name} reused, got {name}:\n{launch_output}"
    assert "marked persistent" in launch_output, f"want the reuse notice:\n{launch_output}"
    assert "leftover" not in launch_output, f"container treated as a leftover:\n{launch_output}"
    assert incus_status(calculate_container_name(workspace_dir, 2)) == "", "slot 2 was launched"

    rc, out = exec_in(coi_binary, container_name, f"cat {marker}")
    assert rc == 0 and "kept" in out, f"marker lost after restart: {out}"
