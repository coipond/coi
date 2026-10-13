"""
Test profile inheritance for array fields.

Tests that arrays (mounts, forward_env) replace when child defines them
and are inherited when child does not.
"""

import os
import subprocess
from pathlib import Path


def test_profile_inheritance_mounts_replaced(coi_binary, cleanup_containers, workspace_dir):
    """Child defines mounts - parent's mounts gone."""
    coi_dir = Path(workspace_dir) / ".coi" / "profiles"

    parent_dir = coi_dir / "parent"
    parent_dir.mkdir(parents=True)
    (parent_dir / "config.toml").write_text(
        '[[mounts]]\nhost = "~/.ssh"\ncontainer = "/home/code/.ssh"\n'
    )

    child_dir = coi_dir / "child"
    child_dir.mkdir(parents=True)
    (child_dir / "config.toml").write_text(
        'inherits = "parent"\n\n[[mounts]]\nhost = "~/.cargo"\ncontainer = "/home/code/.cargo"\n'
    )

    result = subprocess.run(
        [coi_binary, "profile", "info", "child", "--workspace", workspace_dir],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    output = result.stdout + result.stderr
    assert "~/.cargo" in output, f"Should have child mount. Got:\n{output}"
    assert "~/.ssh" not in output, f"Parent mount should be replaced. Got:\n{output}"


def test_profile_inheritance_mounts_inherited(coi_binary, cleanup_containers, workspace_dir):
    """Child without mounts gets parent's mounts."""
    coi_dir = Path(workspace_dir) / ".coi" / "profiles"

    parent_dir = coi_dir / "parent"
    parent_dir.mkdir(parents=True)
    (parent_dir / "config.toml").write_text(
        '[[mounts]]\nhost = "~/.ssh"\ncontainer = "/home/code/.ssh"\n'
    )

    child_dir = coi_dir / "child"
    child_dir.mkdir(parents=True)
    (child_dir / "config.toml").write_text(
        'inherits = "parent"\n[container]\nimage = "coi-child"\n'
    )

    result = subprocess.run(
        [coi_binary, "profile", "info", "child", "--workspace", workspace_dir],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    output = result.stdout + result.stderr
    assert "~/.ssh" in output, f"Should inherit parent mounts. Got:\n{output}"


def test_profile_inheritance_forward_env_replaced(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """Child defines forward_env - replaces parent's."""
    # forward_env is trusted-scope only: keep these profiles next to $COI_CONFIG.
    user_config = tmp_path / "config.toml"
    user_config.write_text("")
    coi_dir = tmp_path / "profiles"

    parent_dir = coi_dir / "parent"
    parent_dir.mkdir(parents=True)
    (parent_dir / "config.toml").write_text('forward_env = ["SSH_AUTH_SOCK"]\n')

    child_dir = coi_dir / "child"
    child_dir.mkdir(parents=True)
    (child_dir / "config.toml").write_text('inherits = "parent"\nforward_env = ["API_KEY"]\n')

    result = subprocess.run(
        [coi_binary, "profile", "info", "child", "--workspace", workspace_dir],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
        env={**os.environ, "COI_CONFIG": str(user_config)},
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    output = result.stdout + result.stderr
    assert "API_KEY" in output, f"Should have child forward_env. Got:\n{output}"
    assert "SSH_AUTH_SOCK" not in output, f"Parent forward_env replaced. Got:\n{output}"


def test_profile_inheritance_forward_env_inherited(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """Child without forward_env gets parent's."""
    # forward_env is trusted-scope only: keep these profiles next to $COI_CONFIG.
    user_config = tmp_path / "config.toml"
    user_config.write_text("")
    coi_dir = tmp_path / "profiles"

    parent_dir = coi_dir / "parent"
    parent_dir.mkdir(parents=True)
    (parent_dir / "config.toml").write_text('forward_env = ["SSH_AUTH_SOCK"]\n')

    child_dir = coi_dir / "child"
    child_dir.mkdir(parents=True)
    (child_dir / "config.toml").write_text(
        'inherits = "parent"\n[container]\nimage = "coi-default"\n'
    )

    result = subprocess.run(
        [coi_binary, "profile", "info", "child", "--workspace", workspace_dir],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
        env={**os.environ, "COI_CONFIG": str(user_config)},
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    output = result.stdout + result.stderr
    assert "SSH_AUTH_SOCK" in output, f"Should inherit parent forward_env. Got:\n{output}"
