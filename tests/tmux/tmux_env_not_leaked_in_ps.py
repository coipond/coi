"""
Test that forwarded environment variables are NOT leaked in bash command lines.

Regression test for the fix in PR #352: environment variables forwarded into
tmux sessions must be passed via `tmux new-session -e KEY=VAL` flags rather
than inlined as `export KEY=VAL; ...` in the shell command string.

The old implementation used `bash -c 'export KEY=VAL; ...'` which leaked
secrets in the bash process's command line (visible via `ps auxww`).
The new implementation passes them via tmux's `-e` flag, keeping the bash
shell command clean.

Tests that:
1. Launch coi shell --background with forward_env containing a secret
2. Verify `bash -c` process lines do NOT contain the secret value
3. Verify no `export KEY=` patterns appear in ps output
4. Verify the secret IS available inside the tmux session (functional correctness)
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


def test_forwarded_env_not_visible_in_ps(coi_binary, cleanup_containers, workspace_dir):
    """
    Forwarded env vars must NOT appear in bash command lines in ps output.

    The old implementation inlined `export KEY=VAL; ...` into the bash command
    string, which made secrets (GITHUB_TOKEN, etc.) visible in the bash process
    command line when running `ps auxww`.

    The fix uses `tmux new-session -e KEY=VAL` which keeps values out of the
    bash process command line. (The tmux server process itself may still show
    the `-e` flags, but the critical improvement is that bash shells don't leak
    secrets in their argument list.)

    Flow:
    1. Create .coi/config.toml with forward_env = ["COI_SECRET_TOKEN"]
    2. Set COI_SECRET_TOKEN to a recognisable marker value on the host
    3. Launch coi shell --background (creates a detached tmux session)
    4. Wait for the container to be running and tmux session to exist
    5. Run `ps auxww` inside the container
    6. Assert the marker value does NOT appear in bash command lines
    7. Assert no `export KEY=` pattern in ps output
    8. Assert the variable IS accessible inside the tmux pane (functional check)
    """
    container_name = calculate_container_name(workspace_dir, 1)
    secret_value = "SUPER_SECRET_TOKEN_ps_leak_test_7x9k2m"

    # === Phase 1: Create config with forward_env ===

    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[defaults]
forward_env = ["COI_SECRET_TOKEN"]
"""
    )

    # === Phase 2: Launch shell in background with the secret set ===

    env = os.environ.copy()
    env["COI_CONFIG"] = str(config_dir / "config.toml")  # forward_env is trusted-scope only
    env["COI_USE_DUMMY"] = "1"
    env["COI_SECRET_TOKEN"] = secret_value

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

    # Wait for coi shell --background to finish (it exits after creating the session)
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

    # Print stderr for debugging (shows forward_env warnings if any)
    print(f"\n=== coi shell --background stderr ===\n{stderr.decode()}\n=== end ===")

    # === Phase 3: Wait for container to be running ===

    assert _wait_for_container_running(container_name, timeout=60), (
        f"Container {container_name} never reached Running state"
    )

    # Give tmux session a moment to fully initialise
    time.sleep(3)

    # === Phase 4: Check ps auxww does NOT contain the secret ===

    result = subprocess.run(
        [coi_binary, "container", "exec", "--capture", container_name, "--", "ps", "auxww"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, f"ps auxww should succeed. stderr: {result.stderr}"

    ps_output = result.stdout + result.stderr

    # The PR moves secrets from inline `export KEY=VAL;` in the bash command
    # to tmux `-e KEY=VAL` flags. The tmux server process will show `-e` flags
    # in its command line, but the important fix is that bash process lines
    # no longer contain the secret (the old `export` pattern leaked to all
    # child processes and was visible as a shell command).
    # Extract bash command lines from ps output and verify they don't contain the secret.
    import json as _json

    try:
        ps_data = _json.loads(ps_output)
        ps_lines = ps_data.get("stdout", "").splitlines()
    except (ValueError, KeyError):
        ps_lines = ps_output.splitlines()

    # Filter for actual bash processes, excluding the tmux server line
    # (which contains `bash -c` as a session command argument).
    bash_lines = [line for line in ps_lines if "bash -c" in line and "tmux" not in line]
    for line in bash_lines:
        assert secret_value not in line, (
            f"SECRET VALUE LEAKED IN BASH COMMAND LINE! "
            f"The secret '{secret_value}' must NOT appear in `bash -c` process lines. "
            f"This means environment variables are being inlined as `export KEY=VAL;` "
            f"in the shell command string rather than passed via tmux -e flags.\n\n"
            f"Offending line:\n{line}\n\n"
            f"Full ps output:\n{ps_output}"
        )

    # Also verify that `export COI_SECRET_TOKEN=` doesn't appear anywhere in ps
    assert "export COI_SECRET_TOKEN=" not in ps_output, (
        f"REGRESSION: 'export COI_SECRET_TOKEN=' found in ps output! "
        f"Environment variables must NOT be passed as inline export statements.\n\n"
        f"ps output:\n{ps_output}"
    )

    # === Phase 5: Verify the variable IS available inside the tmux pane ===
    # The tmux pane starts with the dummy CLI. Exit it to get bash
    # (session cmd: bash -c 'trap : INT; dummy ...; exec bash')

    tmux_session = f"coi-{container_name}"

    # Exit the dummy CLI to drop into bash
    subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--user",
            "1000",
            "--",
            "tmux",
            "send-keys",
            "-t",
            tmux_session,
            "exit",
            "Enter",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    time.sleep(3)

    # Now send echo command in bash
    subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--user",
            "1000",
            "--",
            "tmux",
            "send-keys",
            "-t",
            tmux_session,
            "echo ENV_CHECK_${COI_SECRET_TOKEN}_END",
            "Enter",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    time.sleep(2)

    # Capture pane output
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
            "capture-pane",
            "-t",
            tmux_session,
            "-p",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, f"tmux capture-pane should succeed. stderr: {result.stderr}"

    pane_output = result.stdout + result.stderr
    assert f"ENV_CHECK_{secret_value}_END" in pane_output, (
        f"Forwarded env var should be accessible inside the tmux session. "
        f"Expected 'ENV_CHECK_{secret_value}_END' in pane output.\n"
        f"Got:\n{pane_output}"
    )

    # === Phase 6: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
