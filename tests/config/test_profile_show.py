"""
Test coi profile show command.

Tests that:
1. Shows all profile fields correctly
2. Handles non-existent profile name
3. Shows directory profile details including resolved paths
"""

import os
import subprocess
from pathlib import Path


def test_profile_show_full(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    Test that coi profile show displays all fields of a profile.

    The profile lives next to $COI_CONFIG (trusted scope): forward_env is
    stripped from a project-scoped profile.
    """
    user_config = tmp_path / "config.toml"
    user_config.write_text("")
    profile_dir = tmp_path / "profiles" / "fullprof"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
forward_env = ["MY_KEY"]

[container]
image = "coi-full"
persistent = true

[environment]
MY_VAR = "hello"

[tool]
name = "claude"
permission_mode = "bypass"

[tool.claude]
effort_level = "high"

[[mounts]]
host = "~/.config"
container = "/home/code/.config"

[limits.cpu]
count = "4"

[network]
mode = "restricted"
"""
    )

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "info",
            "fullprof",
            "--workspace",
            workspace_dir,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
        env={**os.environ, "COI_CONFIG": str(user_config)},
    )

    assert result.returncode == 0, f"profile show should succeed. stderr: {result.stderr}"
    output = result.stdout + result.stderr

    assert "fullprof" in output, f"Should show profile name. Got:\n{output}"
    assert "coi-full" in output, f"Should show image. Got:\n{output}"
    assert "true" in output, f"Should show persistent. Got:\n{output}"
    assert "MY_KEY" in output, f"Should show forward_env. Got:\n{output}"
    assert "MY_VAR" in output, f"Should show environment key. Got:\n{output}"
    assert "claude" in output, f"Should show tool name. Got:\n{output}"
    assert "bypass" in output, f"Should show permission mode. Got:\n{output}"
    assert "high" in output, f"Should show effort level. Got:\n{output}"
    assert "~/.config" in output, f"Should show mount host. Got:\n{output}"
    assert "4" in output, f"Should show CPU count. Got:\n{output}"
    assert "restricted" in output, f"Should show network mode. Got:\n{output}"


def test_profile_show_not_found(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that coi profile show with non-existent name fails.
    """
    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "info",
            "nonexistent",
            "--workspace",
            workspace_dir,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    assert result.returncode != 0, "profile show should fail for non-existent profile"
    combined = result.stdout + result.stderr
    assert "not found" in combined.lower(), (
        f"Error should mention profile not found. Got:\n{combined}"
    )


def test_profile_show_empty_directory_profile(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that a profile directory with minimal config (just an image) shows correctly.
    """
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "minimal"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text('[container]\nimage = "coi-default"\n')

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "info",
            "minimal",
            "--workspace",
            workspace_dir,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"profile show should succeed. stderr: {result.stderr}"
    output = result.stdout + result.stderr
    assert "minimal" in output, f"Should show profile name. Got:\n{output}"
    assert "coi" in output, f"Should show image. Got:\n{output}"
