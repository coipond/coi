"""Issue #610 (coi shell seam): a persistent shell container whose protected path
was removed while stopped must still restart on `coi shell --resume`.

Issue #610 was originally reported from `coi shell` ("setup-container: failed to
setup session: failed to start container: ... Missing source path"). The `coi
run` regressions live in tests/git_hooks/test_issue_610_stale_protect_devices.py;
this proves the SAME fix is wired on the shell restart seam (session.Setup's
stopped-restart branch: strip the stale security devices + re-run the validated
security setup before Start()).

Flow:
1. Start a persistent shell session (materializes .husky as a protected dir).
2. Poweroff — the container stays stopped in persistent mode.
3. Remove .husky from the host workspace while the container is stopped.
4. `coi shell --resume` must bring the SAME container up (no "Missing source
   path" wedge), and .husky must be re-materialized (protection re-established).
"""

import shutil
import subprocess
import time
from pathlib import Path

from support.helpers import (
    calculate_container_name,
    exit_tool_to_bash,
    get_container_list,
    poweroff_session,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    write_trusted_coi_config,
)


def _exit_cli_poweroff_and_close(child):
    """Exit the dummy CLI to bash FIRST, then poweroff. Sending poweroff while the
    interactive CLI is focused would be eaten as CLI input, leaving the container
    running (so the next --resume attaches to a live tmux session instead of
    restarting the stopped one)."""
    assert exit_tool_to_bash(child), "the tool should exit to bash"
    poweroff_session(child)
    time.sleep(3)


def _close(child):
    try:
        child.close(force=True)
    except Exception:
        pass
    time.sleep(2)


def test_shell_resume_after_removed_protected_path(coi_binary, cleanup_containers, workspace_dir):
    # host_immutable is on by default, which chattr +i's protected paths; a
    # persistent shell keeps those flags across poweroff, so the host .husky
    # would be undeletable by this test. host_immutable is orthogonal to the #610
    # device reconcile under test, so disable it via TRUSTED config (a
    # protection-weakening toggle honored only from COI_CONFIG scope). The same
    # trusted config carries [network] open and [container] persistent.
    env = write_trusted_coi_config(
        '[network]\nmode = "open"\n\n[container]\npersistent = true\n\n'
        "[security]\nhost_immutable = false\n"
    )
    env["COI_USE_DUMMY"] = "1"
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: first persistent shell session materializes .husky, then stops ===
    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    husky = Path(workspace_dir) / ".husky"
    assert husky.exists() and husky.is_dir(), (
        ".husky must be materialized as a protected dir by the first shell session"
    )

    _exit_cli_poweroff_and_close(child)

    # Container is kept (persistent) and stopped.
    assert container_name in get_container_list(), (
        f"Persistent container {container_name} should still exist (stopped) after poweroff"
    )

    # === Phase 2: remove the protected source while stopped, then resume ===
    shutil.rmtree(husky)
    assert not husky.exists()

    child2 = spawn_coi(coi_binary, ["shell", "--resume"], cwd=workspace_dir, env=env, timeout=120)

    # THE assertion: the container must come up. If the stale protect-husky device
    # wedged the start (pre-fix #610), Start() fails and the container never becomes
    # ready. (No wait_for_prompt: readiness alone proves the wedge is gone, and the
    # tmux re-attach rendering is an unrelated harness flake surface.)
    wait_for_container_ready(child2, timeout=60)

    # Protection re-established: .husky re-materialized on the host by the reconcile.
    assert husky.exists() and husky.is_dir(), (
        ".husky must be re-materialized after `coi shell --resume` (protection reconcile)"
    )

    # === Cleanup ===
    _close(child2)
    for slot in (1, 2):
        subprocess.run(
            [
                coi_binary,
                "container",
                "delete",
                calculate_container_name(workspace_dir, slot),
                "--force",
            ],
            capture_output=True,
            timeout=30,
        )
