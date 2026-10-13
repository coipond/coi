"""
Test that forwarded env vars are NOT passed as inline `export` statements.

Regression test for PR #352: verifies that the bash command line in ps output
does NOT contain `export KEY=` patterns, which would leak secrets and fail to
propagate to new windows.

This test inspects `ps auxww` output to confirm that `export COI_SECRET=`
never appears in any process command string, and that the secret value itself
doesn't appear in bash shell command lines.
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


def test_no_export_statement_in_tmux_command(coi_binary, cleanup_containers, workspace_dir):
    """
    The tmux pane command must NOT contain inline export statements.

    The old implementation built: `bash -c 'trap : INT; export KEY="VAL"; ... ; exec bash'`
    The new implementation uses: `tmux new-session -e KEY=VAL ... "bash -c 'trap : INT; <cmd>; exec bash'"`

    This test examines `ps auxww` for bash processes that contain `export COI_`
    in their command line, which would indicate the old (insecure) pattern.

    Flow:
    1. Create config with forward_env
    2. Launch coi shell --background
    3. Inspect ps output for `export COI_` pattern
    4. Confirm absence of inline export statements
    """
    container_name = calculate_container_name(workspace_dir, 1)
    secret_value = "no_export_test_value_9z3w"

    # === Phase 1: Create config with forward_env ===

    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[defaults]
forward_env = ["COI_NO_EXPORT_SECRET"]
"""
    )

    # === Phase 2: Launch shell in background ===

    env = os.environ.copy()
    env["COI_CONFIG"] = str(config_dir / "config.toml")  # forward_env is trusted-scope only
    env["COI_USE_DUMMY"] = "1"
    env["COI_NO_EXPORT_SECRET"] = secret_value

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

    # === Phase 3: Wait for container ===

    assert _wait_for_container_running(container_name, timeout=60), (
        f"Container {container_name} never reached Running state"
    )

    time.sleep(3)

    # === Phase 4: Inspect ps output for `export COI_NO_EXPORT_SECRET` ===

    result = subprocess.run(
        [coi_binary, "container", "exec", "--capture", container_name, "--", "ps", "auxww"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, f"ps auxww should succeed. stderr: {result.stderr}"

    ps_output = result.stdout + result.stderr

    # The old pattern would show something like:
    #   bash -c 'trap : INT; export COI_NO_EXPORT_SECRET="no_export_test_value_9z3w"; dummy ...; exec bash'
    # The new pattern should NOT have `export COI_NO_EXPORT_SECRET` anywhere in ps.
    assert "export COI_NO_EXPORT_SECRET" not in ps_output, (
        f"REGRESSION: found 'export COI_NO_EXPORT_SECRET' in ps output! "
        f"Environment variables must NOT be passed as inline export statements "
        f"in the tmux command string. Use tmux -e flags instead.\n\n"
        f"ps output:\n{ps_output}"
    )

    # Verify the secret value doesn't appear in bash command lines.
    # (The tmux server process may show `-e KEY=VAL` in its own command line,
    # which is expected — the key fix is that bash shells don't inline secrets.)
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
            f"REGRESSION: secret value '{secret_value}' found in bash command line! "
            f"Environment variable values must not appear in shell process arguments.\n\n"
            f"Offending line:\n{line}\n\n"
            f"ps output:\n{ps_output}"
        )

    # === Phase 5: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
