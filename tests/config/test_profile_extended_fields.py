"""
Test extended profile fields (git, ssh, security, timezone, paths, incus).

Tests that:
1. Profile show displays all extended sections when set
2. Profile inheritance works for extended struct fields
3. Default profile reflects project config overrides
"""

import os
import subprocess
from pathlib import Path


def test_profile_show_extended_sections(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    Test that coi profile show displays Git/SSH/Security/Timezone/Paths/Incus
    sections when a profile sets them.
    """
    # [ssh] forward_agent = true is trusted-scope only: keep the profile next
    # to $COI_CONFIG rather than in the workspace.
    user_config = tmp_path / "config.toml"
    user_config.write_text("")
    profile_dir = tmp_path / "profiles" / "extprof"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"

[git]
writable_hooks = true

[ssh]
forward_agent = true

[security]
additional_protected_paths = ["/secrets"]

[timezone]
mode = "fixed"
name = "America/New_York"

[paths]
sessions_dir = "/tmp/mysessions"

[incus]
project = "myproject"
"""
    )

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "info",
            "extprof",
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

    # Verify each extended section header and key values appear
    assert "[git]" in output, f"Should show [git] section. Got:\n{output}"
    assert "writable_hooks" in output, f"Should show writable_hooks. Got:\n{output}"

    assert "[ssh]" in output, f"Should show [ssh] section. Got:\n{output}"
    assert "forward_agent" in output, f"Should show forward_agent. Got:\n{output}"
    assert "ignoring '[ssh] forward_agent" not in result.stderr, (
        f"forward_agent was dropped. stderr: {result.stderr}"
    )

    assert "[security]" in output, f"Should show [security] section. Got:\n{output}"
    assert "/secrets" in output, f"Should show protected path. Got:\n{output}"

    assert "[timezone]" in output, f"Should show [timezone] section. Got:\n{output}"
    assert "fixed" in output, f"Should show timezone mode. Got:\n{output}"
    assert "America/New_York" in output, f"Should show timezone name. Got:\n{output}"

    assert "[paths]" in output, f"Should show [paths] section. Got:\n{output}"
    assert "/tmp/mysessions" in output, f"Should show sessions_dir. Got:\n{output}"

    assert "[incus]" in output, f"Should show [incus] section. Got:\n{output}"
    assert "myproject" in output, f"Should show incus project. Got:\n{output}"


def test_profile_inheritance_extended_fields(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    Test that child profile inherits extended fields (git, ssh, security, timezone)
    from parent via mergeProfiles().
    """
    # [ssh] forward_agent = true is trusted-scope only: keep these profiles
    # next to $COI_CONFIG rather than in the workspace.
    user_config = tmp_path / "config.toml"
    user_config.write_text("")
    coi_dir = tmp_path / "profiles"

    parent_dir = coi_dir / "parent"
    parent_dir.mkdir(parents=True)
    (parent_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"

[git]
writable_hooks = true

[ssh]
forward_agent = true

[security]
additional_protected_paths = ["/parent-secrets"]

[timezone]
mode = "fixed"
name = "Europe/London"
"""
    )

    child_dir = coi_dir / "child"
    child_dir.mkdir(parents=True)
    (child_dir / "config.toml").write_text(
        """
inherits = "parent"

[timezone]
name = "Asia/Tokyo"
"""
    )

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "info",
            "child",
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

    # Child should inherit git and ssh from parent (child didn't set them)
    assert "[git]" in output, f"Should inherit [git] from parent. Got:\n{output}"
    assert "writable_hooks" in output, f"Should inherit writable_hooks. Got:\n{output}"

    assert "[ssh]" in output, f"Should inherit [ssh] from parent. Got:\n{output}"
    assert "forward_agent" in output, f"Should inherit forward_agent. Got:\n{output}"
    assert "ignoring '[ssh] forward_agent" not in result.stderr, (
        f"forward_agent was dropped. stderr: {result.stderr}"
    )

    # Child should inherit security from parent
    assert "[security]" in output, f"Should inherit [security] from parent. Got:\n{output}"
    assert "/parent-secrets" in output, f"Should inherit parent protected paths. Got:\n{output}"

    # Child overrides timezone name but should keep parent's mode
    assert "[timezone]" in output, f"Should show [timezone] section. Got:\n{output}"
    assert "Asia/Tokyo" in output, f"Should show child timezone name. Got:\n{output}"
    assert "fixed" in output, f"Should inherit parent timezone mode. Got:\n{output}"


def test_default_profile_reflects_project_config(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that when project .coi/config.toml overrides defaults,
    coi profile show default reflects those overrides.
    """
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[network]
mode = "open"

[timezone]
mode = "fixed"
name = "Pacific/Auckland"
"""
    )

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "info",
            "default",
            "--workspace",
            workspace_dir,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"profile show default should succeed. stderr: {result.stderr}"
    output = result.stdout + result.stderr

    # Network mode should reflect the project override
    assert "open" in output, (
        f"Default profile should reflect project network mode 'open'. Got:\n{output}"
    )

    # Timezone should reflect project override
    assert "Pacific/Auckland" in output, (
        f"Default profile should reflect project timezone. Got:\n{output}"
    )
    assert "fixed" in output, (
        f"Default profile should reflect project timezone mode. Got:\n{output}"
    )
