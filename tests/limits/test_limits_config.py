"""
Test limits configuration loading and merging.

Tests that:
1. Config file limits are loaded correctly
2. Profile limits override global limits
3. Environment variables work
4. Configuration hierarchy is respected
"""

import os
from pathlib import Path

from support.helpers import run_and_show_config, write_workspace_container_config


def test_config_file_limits_loaded(coi_binary, workspace_dir, cleanup_containers):
    """Test that limits from config file are loaded and applied."""
    # Write limits config into the workspace's project config
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "config.toml"
    config_file.write_text(
        """
[container]
image = "coi-default"
persistent = true

[limits.cpu]
count = "2"

[limits.memory]
limit = "1GiB"

[limits.runtime]
max_processes = 100
"""
    )

    # Launch container with coi run (quick test)
    config_output = run_and_show_config(coi_binary, workspace_dir)

    # Check that limits were applied by inspecting container config
    assert 'limits.cpu: "2"' in config_output, "CPU limit should be applied"
    assert "limits.memory: 1GiB" in config_output, "Memory limit should be applied"
    assert 'limits.processes: "100"' in config_output, "Process limit should be applied"


def test_profile_limits_override_global(coi_binary, workspace_dir, cleanup_containers):
    """Test that profile limits override global limits."""
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

    # Launch with profile
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--profile", "limited"]
    )

    # Check that profile limits were applied (not global limits)
    assert 'limits.cpu: "1"' in config_output, "Profile CPU limit should override global"
    assert "limits.memory: 512MiB" in config_output, "Profile memory limit should override global"


def test_environment_variables_removed(coi_binary, workspace_dir, cleanup_containers):
    """COI_LIMIT_* env vars were removed (0.10) — they must NOT set limits."""
    write_workspace_container_config(workspace_dir, persistent=True)

    env = os.environ.copy()
    env["COI_LIMIT_CPU"] = "2"
    env["COI_LIMIT_MEMORY"] = "2GiB"

    config_output = run_and_show_config(coi_binary, workspace_dir, env)

    # The env vars must be ignored — no limits applied
    assert 'limits.cpu: "2"' not in config_output, (
        f"COI_LIMIT_CPU must be ignored (removed in 0.10). Got:\n{config_output}"
    )
    assert "limits.memory: 2GiB" not in config_output, (
        f"COI_LIMIT_MEMORY must be ignored (removed in 0.10). Got:\n{config_output}"
    )


def test_empty_limits_means_unlimited(coi_binary, workspace_dir, cleanup_containers):
    """Test that empty/missing limits result in unlimited (no limits applied)."""
    write_workspace_container_config(workspace_dir, persistent=True)

    # Launch without any limits configured
    config_output = run_and_show_config(coi_binary, workspace_dir)

    # Check that no custom limits were applied (Incus defaults)
    # Should not have custom CPU/memory limits (only Docker security flags)
    # We're checking that we didn't explicitly set limits
    # Note: security.nesting and other Docker flags are OK, we're just checking resource limits
    assert 'limits.cpu: "' not in config_output or 'limits.cpu: ""' in config_output, (
        "No CPU limit should be set"
    )
