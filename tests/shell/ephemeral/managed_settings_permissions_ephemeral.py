"""
Integration test for the managed-settings policy file permissions (PR #606).

coi writes the Claude Code managed-settings policy
(/etc/claude-code/managed-settings.json, which carries `disableAutoMode`, #364)
during `coi shell` session setup. It used to push the file with a plain
`incus file push`, which by default PRESERVES the host temp file's owner and mode
(`--uid`/`--gid` default to -1), so the policy landed owned by the invoking host
UID with the temp file's 0600 mode. Two consequences:

  - On any host whose UID differs from the container's `code` user (macOS's 501,
    CI runners' 1001), the `code` user could not read its own policy, and Claude
    Code refused OAuth with EACCES on the unreadable policy file.
  - On a host whose UID happened to match the `code` user (Linux 1000), the file
    was owned by the sandboxed agent itself, which could then rewrite or delete
    the very policy meant to constrain it.

The fix pushes the file root-owned `0644` in the push itself. This test drives
the real `coi shell` setup — the seam that actually writes the file (setup.go's
`tool.Name() == "claude"` branch). COI_USE_DUMMY keeps the tool identity `claude`
(it only swaps the interactive binary for a stub, so no auth/UI is needed) while
still running the managed-settings step. It then drops to a bash shell as the
unprivileged `code` user and inspects the file:

  * owner:group:mode is `0:0` / `644` (pre-fix: the host UID and mode 600);
  * the `code` user can actually READ it (the EACCES that broke OAuth).
"""

import os
import time

from support.helpers import (
    calculate_container_name,
    poweroff_and_wait,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    wait_for_text_in_monitor,
    with_live_screen,
)

MANAGED_SETTINGS_PATH = "/etc/claude-code/managed-settings.json"


def test_managed_settings_root_owned_and_readable_by_code_user(
    coi_binary, cleanup_containers, workspace_dir
):
    """The policy file must land 0:0 mode 644 and be readable by the code user."""
    # The tool identity must be claude for the managed-settings step to run;
    # COI_USE_DUMMY only replaces the interactive binary with a fast stub.
    config_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "config.toml"), "w") as f:
        f.write('[tool]\nname = "claude"\n')

    env = {"COI_USE_DUMMY": "1"}
    container_name = calculate_container_name(workspace_dir, 1)

    perms_ok = False
    read_ok = False

    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    try:
        wait_for_container_ready(child, timeout=60)
        wait_for_prompt(child, timeout=90)

        # Drop from the (dummy) tool to a bash shell inside the container. This
        # bash runs as the unprivileged `code` user — exactly the identity that
        # must be able to read the managed policy.
        child.send("exit")
        time.sleep(0.3)
        child.send("\x0d")
        time.sleep(2)

        with with_live_screen(child) as monitor:
            time.sleep(1)

            # owner:group:mode. stat only needs the (0755) parent dirs, so it
            # reports the true attributes regardless of the file's own perms.
            child.send(f'echo "MSPERM:$(stat -c %u:%g:%a {MANAGED_SETTINGS_PATH})"')
            time.sleep(0.3)
            child.send("\x0d")
            perms_ok = wait_for_text_in_monitor(monitor, "MSPERM:0:0:644", timeout=15)

            # The load-bearing check: the code user can READ the policy. Pre-fix
            # this printed "Permission denied" (the EACCES OAuth regression).
            child.send(f"cat {MANAGED_SETTINGS_PATH}")
            time.sleep(0.3)
            child.send("\x0d")
            read_ok = wait_for_text_in_monitor(monitor, "disableAutoMode", timeout=15)
    finally:
        poweroff_and_wait(child, coi_binary, container_name)

    assert perms_ok, (
        f"{MANAGED_SETTINGS_PATH} must be root-owned mode 644 (expected the "
        "marker MSPERM:0:0:644 on screen); pre-fix it was owned by the host UID "
        "with mode 600"
    )
    assert read_ok, (
        "the unprivileged 'code' user could not read the managed policy file "
        "(the EACCES OAuth regression that PR #606 fixes)"
    )
