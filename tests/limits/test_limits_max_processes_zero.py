"""
Test that an explicit max_processes = 0 lifts a lower layer's process limit.

Tests that:
1. A user config limit alone reaches the container (control)
2. A project config with max_processes = 0 lifts the user config limit
3. A profile with max_processes = 0 lifts the user config limit
4. A parent profile limit alone reaches the container (control)
5. A child profile with max_processes = 0 lifts its parent's limit
"""

import os
import subprocess
from pathlib import Path

from support.helpers import calculate_container_name


def _write_user_config(tmp_path, content):
    """Write ~/.coi/config.toml under a fake HOME and return the env to use."""
    fake_home = tmp_path / "fake_home"
    (fake_home / ".coi").mkdir(parents=True)
    (fake_home / ".coi" / "config.toml").write_text(content)
    env = os.environ.copy()
    env["HOME"] = str(fake_home)
    env.pop("COI_CONFIG", None)
    return env


def _write_profile(workspace_dir, name, content):
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / name
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(content)


def _run_and_show_config(coi_binary, workspace_dir, env, extra_args=()):
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, *extra_args, "echo", "test"],
        capture_output=True,
        text=True,
        timeout=240,
        cwd=workspace_dir,
        env=env,
    )
    assert result.returncode == 0, f"Command should succeed. stderr: {result.stderr}"

    result = subprocess.run(
        ["incus", "config", "show", "--expanded", calculate_container_name(workspace_dir, 1)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, "Should be able to read container config"
    return result.stdout


USER_LIMIT_500 = """
[container]
persistent = true

[limits.runtime]
max_processes = 500
"""

PARENT_PROFILE_500 = """
[container]
image = "coi-default"
persistent = true

[limits.runtime]
max_processes = 500
"""

UNLIMITED = """
[limits.runtime]
max_processes = 0
"""


def test_user_config_process_limit_applied(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """Test that the user config limit alone is set on the container."""
    env = _write_user_config(tmp_path, USER_LIMIT_500)

    config = _run_and_show_config(coi_binary, workspace_dir, env)

    assert 'limits.processes: "500"' in config, (
        f"User config process limit should be set. Config: {config}"
    )


def test_project_zero_lifts_user_process_limit(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """Test that project max_processes = 0 lifts the user config limit."""
    env = _write_user_config(tmp_path, USER_LIMIT_500)
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(UNLIMITED)

    config = _run_and_show_config(coi_binary, workspace_dir, env)

    assert "limits.processes" not in config, (
        f"Project max_processes = 0 should lift the user limit. Config: {config}"
    )


def test_profile_zero_lifts_user_process_limit(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """Test that profile max_processes = 0 lifts the user config limit."""
    env = _write_user_config(tmp_path, USER_LIMIT_500)
    _write_profile(workspace_dir, "unlimited", UNLIMITED)

    config = _run_and_show_config(coi_binary, workspace_dir, env, ["--profile", "unlimited"])

    assert "limits.processes" not in config, (
        f"Profile max_processes = 0 should lift the user limit. Config: {config}"
    )


def test_parent_profile_process_limit_applied(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """Test that the parent profile limit alone is set on the container."""
    env = _write_user_config(tmp_path, "")
    _write_profile(workspace_dir, "parent", PARENT_PROFILE_500)

    config = _run_and_show_config(coi_binary, workspace_dir, env, ["--profile", "parent"])

    assert 'limits.processes: "500"' in config, (
        f"Parent profile process limit should be set. Config: {config}"
    )


def test_child_profile_zero_lifts_parent_process_limit(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """Test that child profile max_processes = 0 lifts its parent's limit."""
    env = _write_user_config(tmp_path, "")
    _write_profile(workspace_dir, "parent", PARENT_PROFILE_500)
    _write_profile(workspace_dir, "child", 'inherits = "parent"\n' + UNLIMITED)

    config = _run_and_show_config(coi_binary, workspace_dir, env, ["--profile", "child"])

    assert "limits.processes" not in config, (
        f"Child profile max_processes = 0 should lift the parent limit. Config: {config}"
    )
