"""
Test limits configuration precedence.

Tests that:
1. Config file values are applied correctly
2. Profile values override global config values
3. Environment variables work alongside config
4. Precedence chain: Profile > Config > Env > Default
"""

import os
from pathlib import Path

from support.helpers import run_and_show_config, write_workspace_container_config


def test_config_values_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that config file limit values are applied correctly."""
    # Create project config with limits
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    (project_config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "2"

[limits.memory]
limit = "2GiB"
"""
    )

    # Launch without any extra flags -- config should be applied
    config_output = run_and_show_config(coi_binary, workspace_dir)

    # Verify config values were applied
    assert 'limits.cpu: "2"' in config_output, "Config CPU limit should be applied"
    assert "limits.memory: 2GiB" in config_output, "Config memory limit should be applied"


def test_profile_overrides_config(coi_binary, workspace_dir, cleanup_containers):
    """Test that profile settings override global config."""
    # Create project config with global limits
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    project_config = project_config_dir / "config.toml"
    config_content = """
[container]
persistent = true

[limits.cpu]
count = "4"

[limits.memory]
limit = "4GiB"
"""
    project_config.write_text(config_content)

    # Create directory profile with overriding limits
    profile_dir = project_config_dir / "profiles" / "limited"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"

[limits.cpu]
count = "1"

[limits.memory]
limit = "512MiB"
"""
    )

    # Launch with profile (no CLI flags)
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--profile", "limited"]
    )

    # Verify profile limits took precedence over global config
    assert 'limits.cpu: "1"' in config_output, (
        "Profile CPU limit should override global config (should be 1, not 4)"
    )
    assert "limits.memory: 512MiB" in config_output, (
        "Profile memory limit should override global config (should be 512MiB, not 4GiB)"
    )


def test_limit_env_vars_removed(coi_binary, workspace_dir, cleanup_containers):
    """COI_LIMIT_* env vars were removed (0.10): limits are config-only.
    Setting them must NOT apply any limits."""
    write_workspace_container_config(workspace_dir, persistent=True)

    env = os.environ.copy()
    env["COI_LIMIT_CPU"] = "1"
    env["COI_LIMIT_MEMORY"] = "512MiB"

    # Launch with env vars set and no limits config file
    config_output = run_and_show_config(coi_binary, workspace_dir, env)

    # The env vars must be ignored — no limits applied
    assert 'limits.cpu: "1"' not in config_output, (
        f"COI_LIMIT_CPU must be ignored (removed in 0.10). Got:\n{config_output}"
    )
    assert "limits.memory: 512MiB" not in config_output, (
        f"COI_LIMIT_MEMORY must be ignored (removed in 0.10). Got:\n{config_output}"
    )


def test_config_wins_over_removed_env_vars(coi_binary, workspace_dir, cleanup_containers):
    """Config limits apply; COI_LIMIT_* env vars are ignored (removed in 0.10)."""
    # Create project config with limits
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    (project_config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "4"

[limits.memory]
limit = "4GiB"
"""
    )

    env = os.environ.copy()
    env["COI_LIMIT_CPU"] = "1"
    env["COI_LIMIT_MEMORY"] = "512MiB"

    # Launch with both config and env vars
    config_output = run_and_show_config(coi_binary, workspace_dir, env)

    # Env-var overrides were removed: the CONFIG values must win.
    assert 'limits.cpu: "4"' in config_output, (
        f"Config CPU limit must apply (env var ignored). Got:\n{config_output}"
    )
    assert "limits.memory: 4GiB" in config_output, (
        f"Config memory limit must apply (env var ignored). Got:\n{config_output}"
    )


def test_config_with_multiple_limit_sections(coi_binary, workspace_dir, cleanup_containers):
    """Test that config with multiple limit sections is applied correctly."""
    # Create project config with multiple limit sections
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    (project_config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "4"

[limits.memory]
limit = "4GiB"

[limits.runtime]
max_processes = 100
"""
    )

    # Launch without any extra flags
    config_output = run_and_show_config(coi_binary, workspace_dir)

    # Verify all config values
    assert 'limits.cpu: "4"' in config_output, "CPU should be set from config"
    assert "limits.memory: 4GiB" in config_output, "Memory should be set from config"
    assert 'limits.processes: "100"' in config_output, "Processes should be set from config"


def test_profile_partial_override_of_config(coi_binary, workspace_dir, cleanup_containers):
    """Test that profile can partially override config (only specified values override)."""
    # Create project config with multiple limits
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    (project_config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "4"

[limits.memory]
limit = "4GiB"

[limits.runtime]
max_processes = 100
"""
    )

    # Create directory profile that only overrides CPU
    profile_dir = project_config_dir / "profiles" / "partial"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"

[limits.cpu]
count = "2"
"""
    )

    # Launch with profile (only CPU should be overridden)
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--profile", "partial"]
    )

    # Verify partial override
    assert 'limits.cpu: "2"' in config_output, "CPU should be overridden to 2 by profile"
    assert "limits.memory: 4GiB" in config_output, "Memory should remain from config (4GiB)"
    assert 'limits.processes: "100"' in config_output, "Processes should remain from config (100)"
