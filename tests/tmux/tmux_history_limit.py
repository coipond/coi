"""
Test for tmux history-limit default in the coi-default image.

Regression for https://github.com/mensfeld/coi/issues/312:
`coi shell` wraps the interactive session in tmux, and tmux's stock
default history-limit of 2000 lines silently truncated the start of long
command outputs (e.g. `bin/setup` in a Rails app). The fix ships
`/etc/tmux.conf` with `set -g history-limit 50000` in the default image.

Tests that:
1. /etc/tmux.conf exists in the default image and declares the 50000 limit.
2. A freshly launched tmux session in the container actually honours that
   value — so even if tmux config loading ever changes, the end-to-end
   behaviour is covered.
"""

import subprocess
import time

from support.helpers import calculate_container_name


def test_tmux_history_limit_default(coi_binary, cleanup_containers, workspace_dir):
    """
    The default image must ship /etc/tmux.conf with history-limit=50000,
    and a new tmux session inside the container must actually use that
    value.
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

    # === Phase 2: /etc/tmux.conf is present and declares the 50000 limit ===

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
    # `coi container exec` routes the command's stdout through its own
    # stderr when not running with a TTY, so check both streams.
    combined_cat = result.stdout + result.stderr
    assert "set -g history-limit 50000" in combined_cat, (
        f"/etc/tmux.conf must set history-limit to 50000. Got:\n{combined_cat}"
    )

    # === Phase 3: A fresh tmux session honours the configured value ===
    #
    # Run as the `code` user (UID 1000) — that's who actually launches
    # tmux when a real `coi shell` session starts. Running as root would
    # miss regressions where /etc/tmux.conf is unreadable to non-root,
    # or where a user-level config silently overrides the system setting.

    tmux_session = f"coi-{container_name}-histlimit"

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
            "history-limit",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"tmux show-options should succeed. stderr: {result.stderr}"
    # `coi container exec` may route command stdout through its stderr
    # when no TTY is attached — check both. `tmux show-options -gv`
    # prints just the value, so we assert exact equality (a substring
    # match would happily accept "150000" or "500000").
    combined_show = (result.stdout + result.stderr).strip()
    assert combined_show == "50000", (
        f"tmux history-limit must be exactly 50000 in a default-image session. "
        f"Got: stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    # === Phase 4: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
