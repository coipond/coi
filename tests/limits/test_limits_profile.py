"""
Test profile-specific limits.

Tests that:
1. Profiles can define their own limits
2. Profile limits override global config limits
3. Multiple profiles can have different limits
4. Profile limits work correctly with global config
"""

import subprocess
from pathlib import Path

from support.helpers import calculate_container_name, run_and_show_config


def test_profile_with_limits(coi_binary, workspace_dir, cleanup_containers):
    """Test that profile limits are applied when using a profile."""
    # Create directory profile with limits
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "limited"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"
persistent = true

[limits.cpu]
count = "2"
allowance = "50%"

[limits.memory]
limit = "2GiB"
enforce = "hard"

[limits.disk]
read = "10MB"

[limits.runtime]
max_processes = 50
"""
    )

    # Launch with profile
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--profile", "limited"]
    )

    # Verify all profile limits were applied
    assert 'limits.cpu: "2"' in config_output, "Profile CPU count should be applied"
    assert "limits.cpu.allowance: 50%" in config_output, "Profile CPU allowance should be applied"
    assert "limits.memory: 2GiB" in config_output, "Profile memory limit should be applied"
    assert "limits.memory.enforce: hard" in config_output, (
        "Profile memory enforce should be applied"
    )
    assert "limits.read: 10MB" in config_output, "Profile disk read limit should be applied"
    assert 'limits.processes: "50"' in config_output, "Profile process limit should be applied"


def test_multiple_profiles_different_limits(coi_binary, workspace_dir, cleanup_containers):
    """Test that different profiles can have different limits."""
    # Create two directory profiles with different limits
    for name, cpu, memory in [("small", "1", "512MiB"), ("large", "4", "8GiB")]:
        profile_dir = Path(workspace_dir) / ".coi" / "profiles" / name
        profile_dir.mkdir(parents=True)
        (profile_dir / "config.toml").write_text(
            f"""
[container]
image = "coi-default"
persistent = true

[limits.cpu]
count = "{cpu}"

[limits.memory]
limit = "{memory}"
"""
        )

    # Test small profile
    container_name_1 = calculate_container_name(workspace_dir, 1)
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--slot=1", "--profile", "small"]
    )
    assert 'limits.cpu: "1"' in config_output, "Small profile should have 1 CPU"
    assert "limits.memory: 512MiB" in config_output, "Small profile should have 512MiB memory"

    # Clean up first container
    subprocess.run(
        [coi_binary, "container", "delete", container_name_1, "--force"],
        capture_output=True,
        timeout=30,
    )

    # Test large profile
    container_name_2 = calculate_container_name(workspace_dir, 2)
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--slot=2",
            "--profile",
            "large",
            "echo",
            "large",
        ],
        capture_output=True,
        text=True,
        timeout=240,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"Large profile should succeed. stderr: {result.stderr}"

    result = subprocess.run(
        ["incus", "config", "show", container_name_2],
        capture_output=True,
        text=True,
        timeout=30,
    )

    config_output = result.stdout
    assert 'limits.cpu: "4"' in config_output, "Large profile should have 4 CPUs"
    assert "limits.memory: 8GiB" in config_output, "Large profile should have 8GiB memory"


def test_profile_partial_limits(coi_binary, workspace_dir, cleanup_containers):
    """Test that profile can define only some limits (others remain unset)."""
    # Create profile with only CPU limit
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "cpu_only"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"
persistent = true

[limits.cpu]
count = "2"
"""
    )

    # Launch with profile
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--profile", "cpu_only"]
    )

    # Verify only CPU limit is set
    assert 'limits.cpu: "2"' in config_output, "CPU limit should be set from profile"
    # Memory should not be set (or be empty)
    assert "limits.memory:" not in config_output or 'limits.memory: ""' in config_output, (
        "Memory limit should not be set (profile didn't specify it)"
    )


def test_profile_limits_with_global_config(coi_binary, workspace_dir, cleanup_containers):
    """Test interaction between global config limits and profile limits."""
    # Create config with global limits
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    project_config = project_config_dir / "config.toml"
    config_content = """
# Global limits
[limits.cpu]
count = "4"

[limits.memory]
limit = "8GiB"

[limits.runtime]
max_processes = 200
"""
    project_config.write_text(config_content)

    # Create directory profile with partial overrides
    profile_dir = project_config_dir / "profiles" / "override"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"
persistent = true

[limits.cpu]
count = "1"

# Profile doesn't override memory or processes, so global should apply
"""
    )

    # Launch with profile
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--profile", "override"]
    )

    # Verify profile CPU override but global memory/processes
    assert 'limits.cpu: "1"' in config_output, "Profile should override CPU (should be 1, not 4)"
    assert "limits.memory: 8GiB" in config_output, (
        "Global memory should apply (profile didn't override)"
    )
    assert 'limits.processes: "200"' in config_output, (
        "Global process limit should apply (profile didn't override)"
    )


def test_profile_overrides_global_config_limits(coi_binary, workspace_dir, cleanup_containers):
    """Test that profile limits override global config limits."""
    # Create global config with limits
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    (project_config_dir / "config.toml").write_text(
        """
[limits.cpu]
count = "2"

[limits.memory]
limit = "2GiB"
"""
    )

    # Create directory profile with higher limits
    profile_dir = project_config_dir / "profiles" / "bigger"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"
persistent = true

[limits.cpu]
count = "4"

[limits.memory]
limit = "4GiB"
"""
    )

    # Launch with profile -- profile limits should override global config
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--profile", "bigger"]
    )

    # Verify profile limits overrode global config
    assert 'limits.cpu: "4"' in config_output, (
        "Profile should override global config CPU (should be 4, not 2)"
    )
    assert "limits.memory: 4GiB" in config_output, (
        "Profile should override global config memory (should be 4GiB, not 2GiB)"
    )


def test_profile_without_limits_uses_global(coi_binary, workspace_dir, cleanup_containers):
    """Test that profile without limits falls back to global config."""
    # Create config with global limits
    project_config_dir = Path(workspace_dir) / ".coi"
    project_config_dir.mkdir(exist_ok=True)
    project_config = project_config_dir / "config.toml"
    config_content = """
[limits.cpu]
count = "2"

[limits.memory]
limit = "2GiB"
"""
    project_config.write_text(config_content)

    # Create directory profile without limits
    profile_dir = project_config_dir / "profiles" / "nolimits"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[container]
image = "coi-default"
persistent = true
# No limits defined in profile
"""
    )

    # Launch with profile that has no limits
    config_output = run_and_show_config(
        coi_binary, workspace_dir, extra_args=["--profile", "nolimits"]
    )

    # Verify global limits were applied
    assert 'limits.cpu: "2"' in config_output, "Global CPU limit should apply"
    assert "limits.memory: 2GiB" in config_output, "Global memory limit should apply"
