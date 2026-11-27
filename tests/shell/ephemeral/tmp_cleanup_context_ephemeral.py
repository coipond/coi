"""
Test that `coi shell` applies [limits.disk] tmp_max_size / tmp_max_age and
tells the agent about them in ~/SANDBOX_CONTEXT.md.

This launches an ephemeral shell with tmp_max_size=1GiB and tmp_max_age=3d,
copies the context line and the two files coi writes to a workspace file
(which persists to the host), and checks them.
"""

import time
from pathlib import Path

from pexpect import EOF, TIMEOUT

from support.helpers import (
    make_workspace_writable,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
)


def test_shell_tmp_cleanup_limits_and_context_ephemeral(
    coi_binary, cleanup_containers, workspace_dir
):
    """coi shell writes the /tmp cleanup limits and names them in the context."""
    make_workspace_writable(workspace_dir)
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(exist_ok=True)
    (coi_dir / "config.toml").write_text(
        '[limits.disk]\ntmp_max_size = "1GiB"\ntmp_max_age = "3d"\n'
    )

    result_file = Path(workspace_dir) / "tmp_cleanup.txt"

    child = spawn_coi(
        coi_binary,
        ["shell", f"--workspace={workspace_dir}"],
        cwd=workspace_dir,
        env={"COI_USE_DUMMY": "1"},
        timeout=120,
    )
    try:
        wait_for_container_ready(child, timeout=60)
        wait_for_prompt(child, timeout=90)

        # Exit the (dummy) tool to a bash prompt.
        child.send("exit")
        time.sleep(0.3)
        child.send("\x0d")
        time.sleep(3)

        child.send(
            "{ grep -F '/tmp cleanup' ~/SANDBOX_CONTEXT.md; "
            "cat /etc/default/coi-tmp-cleanup /etc/tmpfiles.d/coi-tmp-cleanup.conf; "
            "} > /workspace/tmp_cleanup.txt"
        )
        time.sleep(0.5)
        child.send("\x0d")
        time.sleep(3)

        child.send("exit")
        time.sleep(0.3)
        child.send("\x0d")
        try:
            child.expect(EOF, timeout=30)
        except TIMEOUT:
            pass
    finally:
        try:
            child.close(force=True)
        except Exception:
            pass

    time.sleep(2)
    assert result_file.exists(), "container did not write the result file to the workspace"
    out = result_file.read_text()
    assert "files unused for 3d are deleted" in out, f"context should name tmp_max_age:\n{out}"
    assert "once /tmp holds over 1GiB" in out, f"context should name tmp_max_size:\n{out}"
    assert f"TMP_MAX_BYTES={1 << 30}" in out, f"tmp_max_size not applied:\n{out}"
    assert "D /tmp 1777 root root 3d" in out, f"tmp_max_age not applied:\n{out}"
