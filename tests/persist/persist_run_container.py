"""
Test for coi persist - a persisted `coi run` container is kept.

Tests that:
1. An ephemeral `coi run` container (Incus ephemeral property set) persisted
   from outside with `coi persist` loses the ephemeral property
2. When the run ends, its teardown stops the container instead of deleting it,
   and Incus does not delete it on stop
"""

import subprocess
import time
from pathlib import Path

from support.helpers import calculate_container_name, container_config_get, incus_status

# Waits (at most 120 s) for the host to create the file in the workspace.
WAIT_FOR_DONE = "i=0; until [ -e .persist-done ] || [ $i -ge 120 ]; do sleep 1; i=$((i+1)); done"


def test_persist_run_container_kept(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. coi run --slot 1 -- sh -c <wait for .persist-done>
    2. coi persist <container> while it runs
    3. Create .persist-done; the run ends
    4. Container exists (stopped)
    """
    container_name = calculate_container_name(workspace_dir, 1)
    argv = [coi_binary, "run", "--workspace", workspace_dir, "--slot", "1"]
    proc = subprocess.Popen(
        [*argv, "--", "sh", "-c", WAIT_FOR_DONE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=workspace_dir,
    )
    try:
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline and incus_status(container_name) != "RUNNING":
            time.sleep(1)
        assert incus_status(container_name) == "RUNNING", "run container did not start"

        result = subprocess.run(
            [coi_binary, "persist", container_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, f"persist should succeed. stderr: {result.stderr}"
        assert container_config_get(container_name, "user.coi.persistent") == "true"

        Path(workspace_dir, ".persist-done").touch()
        output, _ = proc.communicate(timeout=180)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)

    assert proc.returncode == 0, f"run should succeed:\n{output}"
    assert "Cleaning up container" not in output, f"persisted container deleted:\n{output}"
    assert incus_status(container_name) == "STOPPED", (
        f"persisted run container should exist stopped, got {incus_status(container_name)!r}"
        f"\n{output}"
    )
