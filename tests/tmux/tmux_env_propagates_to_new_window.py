"""
Test that forwarded environment variables propagate to new tmux windows.

Regression test for the fix in PR #352: the old implementation only set
environment variables in the initial pane's command string. Any new tmux
window or pane created later (e.g. via `tmux new-window` or `Ctrl+b c`)
would NOT inherit those variables.

The fix uses `tmux set-environment -t <session> KEY VAL` after session
creation, so the tmux server propagates variables to all future windows
and panes in that session.

Tests that:
1. Launch coi shell --background with forward_env
2. Create a new tmux window in the same session
3. Verify the forwarded variable is available in the new window
"""

import json
import os
import subprocess
import time
from pathlib import Path

from support.helpers import calculate_container_name


def _get_container_state(name):
    """Get container state via incus."""
    result = subprocess.run(
        ["incus", "list", name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return "Unknown"
    containers = json.loads(result.stdout)
    return containers[0].get("status", "Unknown") if containers else "Unknown"


def _wait_for_container_running(name, timeout=60):
    """Wait for container to reach Running state."""
    for _ in range(timeout):
        if _get_container_state(name) == "Running":
            return True
        time.sleep(1)
    return False


def test_forwarded_env_available_in_new_tmux_window(coi_binary, cleanup_containers, workspace_dir):
    """
    Forwarded env vars must be available in new tmux windows.

    The old implementation only exported variables inside the initial pane's
    bash command string. When a user ran `tmux new-window` (or `Ctrl+b c`),
    the new window's shell inherited the tmux server's near-empty environment
    and did NOT have the forwarded variables.

    The fix calls `tmux set-environment -t <session> KEY VAL` so all future
    windows inherit the variables automatically.

    Flow:
    1. Create .coi/config.toml with forward_env = ["COI_PROPAGATE_VAR"]
    2. Launch coi shell --background
    3. Wait for session to be ready
    4. Create a new tmux window in the session
    5. Echo the variable in the new window
    6. Verify the variable value appears in the new window's output
    """
    container_name = calculate_container_name(workspace_dir, 1)
    propagate_value = "propagated_value_for_new_window_4h8j"

    # === Phase 1: Create config with forward_env ===

    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[defaults]
forward_env = ["COI_PROPAGATE_VAR"]
"""
    )

    # === Phase 2: Launch shell in background ===

    env = os.environ.copy()
    env["COI_CONFIG"] = str(config_dir / "config.toml")  # forward_env is trusted-scope only
    env["COI_USE_DUMMY"] = "1"
    env["COI_PROPAGATE_VAR"] = propagate_value

    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--background",
            "--workspace",
            workspace_dir,
            "--slot",
            "1",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=workspace_dir,
    )

    try:
        stdout, stderr = proc.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise AssertionError(f"coi shell --background timed out. stderr: {stderr.decode()}")

    assert proc.returncode == 0, (
        f"coi shell --background should succeed. "
        f"stdout: {stdout.decode()}\nstderr: {stderr.decode()}"
    )

    # === Phase 3: Wait for container to be running ===

    assert _wait_for_container_running(container_name, timeout=60), (
        f"Container {container_name} never reached Running state"
    )

    time.sleep(3)

    # === Phase 4: Verify tmux session environment contains the variable ===
    # `tmux show-environment` proves that `set-environment` was called
    # successfully. This is what enables propagation to new windows.

    tmux_session = f"coi-{container_name}"

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            "--capture",
            container_name,
            "--user",
            "1000",
            "--",
            "tmux",
            "show-environment",
            "-t",
            tmux_session,
            "COI_PROPAGATE_VAR",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, f"tmux show-environment should succeed. stderr: {result.stderr}"

    env_output = result.stdout + result.stderr
    assert f"COI_PROPAGATE_VAR={propagate_value}" in env_output, (
        f"Forwarded env var should be stored in tmux session environment via "
        f"set-environment. Expected 'COI_PROPAGATE_VAR={propagate_value}' in "
        f"show-environment output.\n"
        f"This would fail with the old implementation that only inlined "
        f"`export` in the first pane's command string.\n"
        f"Got:\n{env_output}"
    )

    # === Phase 7: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
