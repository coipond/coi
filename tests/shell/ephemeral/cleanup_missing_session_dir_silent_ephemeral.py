"""
Regression test: a missing tool config directory at cleanup time must
not print a scary "Warning: Failed to save session data" — it should
be treated as "nothing to save" and logged silently.

Bug report on 0.8.0:

    [cleanup] Warning: Failed to save session data: failed to pull
    .config/opencode directory: exit status 1

Root cause in `internal/session/cleanup.go`:

    if err := mgr.PullDirectory(stateDir, localConfigDir); err != nil {
        if strings.Contains(err.Error(), "not found") ||
           strings.Contains(err.Error(), "No such file") {
            logger("No %s directory found in container")
            return nil
        }
        return fmt.Errorf("failed to pull %s directory: %w", ...)
    }

Two flaws stacked:

  1. `PullDirectory` in `internal/container/manager.go` used `IncusExec`
     which streams stderr to the terminal but returns only the bare
     `*exec.ExitError` — so the `err.Error()` passed to the substring
     match was just `"exit status 1"`, never the incus message body.
  2. The substring match only looked for "not found" / "No such file",
     but incus actually prints `Error: file does not exist` for a
     missing source path. Even if stderr had been captured, the match
     would still have missed.

Fix: capture stderr in `PullDirectory` into the returned error, and
broaden the substring match in `cleanup.go` to also accept
"does not exist" (case-insensitive). Both flaws are closed in one PR
because either fix alone would still leave the warning visible in
some configurations.

This test reproduces the exact conditions:

  1. Workspace with `[tool] name = "opencode"` in `.coi/config.toml`
     — picks a tool whose `ConfigDirName()` is `.config/opencode`
     (the one from the bug report).
  2. Spawn `coi shell` with `COI_USE_DUMMY=1` so the inner CLI is the
     scripted dummy (no real opencode, no real API calls).
  3. Exit the dummy to bash and `rm -rf ~/.config/opencode` — Coi
     auto-injects `opencode.json` during setup, so the directory
     would otherwise exist. Deleting it inside the container
     guarantees the `PullDirectory` call in cleanup hits the
     "file does not exist" path.
  4. `sudo poweroff` to trigger the stopped-container cleanup branch
     that runs `saveSessionData`.
  5. Collect all pexpect-captured output after EOF.
  6. Assert the scary `Warning: Failed to save session data` string
     is NOT present, and the benign `No .config/opencode directory
     found in container` line IS present.

On master before the fix this test fails — the collected output
contains `Warning: Failed to save session data: failed to pull
.config/opencode directory: exit status 1` and does not contain the
"No .config/opencode directory found" line.
"""

import os
import subprocess
import time
from pathlib import Path

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
)


def test_cleanup_silent_when_tool_config_dir_missing(coi_binary, workspace_dir, cleanup_containers):
    """Cleanup must not warn when the tool's config dir doesn't exist in the container."""
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: tool = opencode + dummy binary ===
    #
    # opencode's ConfigDirName is ".config/opencode" — the exact path
    # from the bug report. COI_USE_DUMMY replaces the opencode binary
    # with the dummy so no API calls and no real TUI.
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text('[tool]\nname = "opencode"\n')

    env = {**os.environ, "COI_USE_DUMMY": "1"}

    # === Phase 2: start coi shell ===
    child = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env=env,
        timeout=180,
    )

    try:
        wait_for_container_ready(child, timeout=90)
        wait_for_prompt(child, timeout=120)

        # === Phase 3: drop to bash, nuke .config/opencode ===
        #
        # Coi's setupCLIConfig writes ~/.config/opencode/opencode.json
        # during container bring-up (via ToolWithConfigDirFiles), so
        # the directory exists by default. Delete it so PullDirectory
        # in cleanup hits the "file does not exist" branch.
        child.send("exit")
        time.sleep(0.3)
        child.send("\x0d")
        time.sleep(3)

        child.send("sudo rm -rf /home/code/.config/opencode")
        time.sleep(0.3)
        child.send("\x0d")
        time.sleep(2)

        # === Phase 4: sudo poweroff → triggers cleanup's saveSessionData ===
        child.send("sudo poweroff")
        time.sleep(0.3)
        child.send("\x0d")

        try:
            child.expect(EOF, timeout=90)
        except TIMEOUT:
            pass

        # === Phase 5: collect all captured output ===
        #
        # spawn_coi attaches a terminal-emulator logfile to the pexpect
        # child; different helper versions expose different accessors.
        # Try each one, then fall back to child.before as a last resort.
        output = ""
        lf = child.logfile_read
        if hasattr(lf, "get_raw_output"):
            output = lf.get_raw_output()
        elif hasattr(lf, "get_output"):
            output = lf.get_output()
        elif hasattr(lf, "get_display"):
            output = lf.get_display()
        elif hasattr(lf, "get_display_stripped"):
            output = lf.get_display_stripped()
        if not output and child.before:
            output = (
                child.before.decode(errors="replace")
                if isinstance(child.before, bytes)
                else child.before
            )

        try:
            child.close(force=False)
        except Exception:
            child.close(force=True)

        # === Phase 6: assert no scary warning, assert silent skip ===
        assert "Warning: Failed to save session data" not in output, (
            "Cleanup should not print a save-session warning when the tool's "
            "config directory legitimately doesn't exist. Output was:\n"
            f"{output}"
        )
        assert "No .config/opencode directory found in container" in output, (
            "Cleanup should log the silent-skip branch when the tool's "
            "config directory doesn't exist, proving the fix engaged. "
            f"Output was:\n{output}"
        )

    finally:
        # === Phase 7: cleanup ===
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            check=False,
            capture_output=True,
            timeout=30,
        )
