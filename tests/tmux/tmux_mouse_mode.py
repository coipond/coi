"""
Test for tmux mouse mode in the coi-default image.

Regression for https://github.com/coipond/coi/issues/930:
With tmux's default `mouse off`, many terminals send the mouse wheel as
Up/Down keys inside `coi shell`, so bash steps through its history instead
of the wheel scrolling the scrollback. The fix ships `/etc/tmux.conf` with
`set -g mouse on` in the default image.

Tests that:
1. /etc/tmux.conf declares mouse on.
2. A freshly launched tmux session in the container, run as the code user,
   actually has mouse mode on.
"""

import subprocess
import time

from support.helpers import calculate_container_name


def test_tmux_mouse_mode_default(coi_binary, cleanup_containers, workspace_dir):
    """
    The default image must ship /etc/tmux.conf with mouse on, and a new tmux
    session inside the container must actually use that value.
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container ===

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    # === Phase 2: /etc/tmux.conf declares mouse on ===

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "cat",
            "/etc/tmux.conf",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"/etc/tmux.conf must exist in the default image. stderr: {result.stderr}"
    )
    combined_cat = result.stdout + result.stderr
    assert "set -g mouse on" in combined_cat, (
        f"/etc/tmux.conf must set mouse on. Got:\n{combined_cat}"
    )

    # === Phase 3: A fresh tmux session as the code user has mouse on ===

    tmux_session = f"coi-{container_name}-mouse"

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--user",
            "1000",
            "--",
            "tmux",
            "new-session",
            "-d",
            "-s",
            tmux_session,
            "bash",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Tmux session creation should succeed. stderr: {result.stderr}"

    time.sleep(1)

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--user",
            "1000",
            "--",
            "tmux",
            "show-options",
            "-gv",
            "mouse",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"tmux show-options should succeed. stderr: {result.stderr}"
    combined_show = (result.stdout + result.stderr).strip()
    assert combined_show == "on", (
        f"tmux mouse must be on in a default-image session. "
        f"Got: stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    # === Phase 4: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
