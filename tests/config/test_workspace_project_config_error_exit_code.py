"""
Test that a bad .coi/config.toml in a --workspace outside the CWD is a config
error.

coi reads <CWD>/.coi/config.toml with the main config; a --workspace in
another directory gets its .coi/config.toml loaded on top.

Tests that:
1. `coi run --workspace <dir>` and `coi shell --workspace <dir>` exit 5
   (config error) on a TOML parse error and on a non-IP `[[ports.map]] listen`
2. the error names the workspace and the cause
3. no container is created
"""

import subprocess
from pathlib import Path

import pytest

from support.helpers import workspace_containers

BAD_CONFIGS = {
    "parse_error": ("this is = not valid toml ][\n", "toml:"),
    "non_ip_listen": (
        '[[ports.map]]\nname = "web"\ncontainer = 8000\nlisten = "localhost"\n',
        "'listen' must be an IP address",
    ),
}

COMMANDS = {
    "run": ["run", "--workspace", "{ws}", "--", "true"],
    "shell": ["shell", "--background", "--workspace", "{ws}"],
}


@pytest.mark.parametrize("config", sorted(BAD_CONFIGS))
@pytest.mark.parametrize("command", sorted(COMMANDS))
def test_workspace_project_config_error_exit_code(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, command, config
):
    """A bad workspace config loaded from another CWD exits 5 before launch."""
    body, cause = BAD_CONFIGS[config]
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir()
    (coi_dir / "config.toml").write_text(body)
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()

    result = subprocess.run(
        [coi_binary, *(arg.format(ws=workspace_dir) for arg in COMMANDS[command])],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=cwd,
    )

    # Should fail with exit code 5 (config error)
    assert result.returncode == 5, (
        f"coi {command} must exit 5, got {result.returncode}. stderr: {result.stderr}"
    )
    assert f"failed to load project config from {workspace_dir}" in result.stderr, (
        f"error should name the workspace. stderr: {result.stderr}"
    )
    assert cause in result.stderr, f"error should name the cause. stderr: {result.stderr}"
    assert not workspace_containers(workspace_dir), "invalid config must abort before launch"
