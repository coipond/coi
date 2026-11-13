"""
Test that limits are actually applied to containers.

Tests that:
1. CPU limits are set correctly
2. Memory limits are set correctly
3. Disk I/O limits are set correctly
4. Process limits are set correctly
5. Multiple limits can be combined
"""

import json
import subprocess
from pathlib import Path

from support.helpers import calculate_container_name, run_and_show_config


def test_cpu_limit_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that CPU limits are applied to the container."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "2"
"""
    )

    config = run_and_show_config(coi_binary, workspace_dir)

    # Verify CPU limit in container config
    assert 'limits.cpu: "2"' in config, f"CPU limit should be set to 2. Config: {config}"


def test_cpu_allowance_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that CPU allowance is applied to the container."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
allowance = "50%"
"""
    )

    config = run_and_show_config(coi_binary, workspace_dir)
    assert "limits.cpu.allowance: 50%" in config, (
        f"CPU allowance should be set to 50%. Config: {config}"
    )


def test_memory_limit_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that memory limits are applied to the container."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.memory]
limit = "2GiB"
"""
    )

    config = run_and_show_config(coi_binary, workspace_dir)
    assert "limits.memory: 2GiB" in config, f"Memory limit should be set to 2GiB. Config: {config}"


def test_memory_swap_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that memory swap configuration is applied."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.memory]
limit = "1GiB"
swap = "false"
"""
    )

    config = run_and_show_config(coi_binary, workspace_dir)
    assert 'limits.memory.swap: "false"' in config, (
        f"Memory swap should be disabled. Config: {config}"
    )


def test_disk_io_limits_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that disk I/O limits are applied to the container."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.disk]
read = "10MB"
write = "5MB"
"""
    )

    config = run_and_show_config(coi_binary, workspace_dir)
    assert "limits.read: 10MB" in config, f"Disk read limit should be set. Config: {config}"
    assert "limits.write: 5MB" in config, f"Disk write limit should be set. Config: {config}"


def test_process_limit_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that process limits are applied to the container."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.runtime]
max_processes = 100
"""
    )

    config = run_and_show_config(coi_binary, workspace_dir)
    assert 'limits.processes: "100"' in config, (
        f"Process limit should be set to 100. Config: {config}"
    )


def test_multiple_limits_combined(coi_binary, workspace_dir, cleanup_containers):
    """Test that multiple limits can be applied together."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "2"

[limits.memory]
limit = "2GiB"

[limits.disk]
read = "10MB"

[limits.runtime]
max_processes = 100
"""
    )

    config = run_and_show_config(coi_binary, workspace_dir)

    assert 'limits.cpu: "2"' in config, "CPU limit should be set"
    assert "limits.memory: 2GiB" in config, "Memory limit should be set"
    assert "limits.read: 10MB" in config, "Disk read limit should be set"
    assert 'limits.processes: "100"' in config, "Process limit should be set"


def test_cpu_priority_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that CPU priority is applied."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "2"
priority = 5
"""
    )

    config = run_and_show_config(coi_binary, workspace_dir)
    assert 'limits.cpu.priority: "5"' in config, (
        f"CPU priority should be set to 5. Config: {config}"
    )


def test_limits_work_with_persistent_containers(coi_binary, workspace_dir, cleanup_containers):
    """Test that limits work with persistent containers."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "2"

[limits.memory]
limit = "2GiB"
"""
    )

    # Launch persistent container with limits
    config = run_and_show_config(coi_binary, workspace_dir)

    assert 'limits.cpu: "2"' in config, "CPU limit should be set"
    assert "limits.memory: 2GiB" in config, "Memory limit should be set"

    # Run again with persistent container (should reuse)
    config = run_and_show_config(coi_binary, workspace_dir)
    assert 'limits.cpu: "2"' in config, "CPU limit should persist"
    assert "limits.memory: 2GiB" in config, "Memory limit should persist"


def test_limits_follow_config_on_persistent_restart(coi_binary, workspace_dir, cleanup_containers):
    """Test that a restarted persistent container gets the current config's limits.

    A raised limit is set and a removed one is unset on the next start.
    """
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    config_file = config_dir / "config.toml"

    config_file.write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "1"

[limits.runtime]
max_processes = 500
"""
    )
    config = run_and_show_config(coi_binary, workspace_dir)
    assert 'limits.cpu: "1"' in config, "CPU limit should be set"
    assert 'limits.processes: "500"' in config, "Process limit should be set"

    config_file.write_text(
        """
[container]
persistent = true

[limits.cpu]
count = "2"
"""
    )
    config = run_and_show_config(coi_binary, workspace_dir)
    assert 'limits.cpu: "2"' in config, "Raised CPU limit should apply on restart"
    assert "limits.processes" not in config, "Removed process limit should be unset"


def _default_root_pool_driver():
    """Resolve the storage driver backing the default profile's root disk.

    Returns the driver string (e.g. "dir", "btrfs", "zfs") or None if it can't
    be determined. Used to branch the disk-size quota test: Incus only enforces
    a root ``size=`` quota on quota-capable drivers, and coi hard-errors on the
    rest (#728).

    ``driver`` is a top-level pool PROPERTY, not a config key, so it must be read
    from ``incus storage list --format json`` — ``incus storage get <pool>
    driver`` returns empty (it only exposes config keys). This mirrors how coi
    itself resolves the driver (container.ListStoragePools).
    """
    pool = subprocess.run(
        ["incus", "profile", "device", "get", "default", "root", "pool"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if pool.returncode != 0 or not pool.stdout.strip():
        return None
    pool_name = pool.stdout.strip()

    listed = subprocess.run(
        ["incus", "storage", "list", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if listed.returncode != 0:
        return None
    try:
        pools = json.loads(listed.stdout)
    except json.JSONDecodeError:
        return None
    for p in pools:
        if p.get("name") == pool_name:
            return p.get("driver") or None
    return None


def test_disk_size_quota_by_pool_driver(coi_binary, workspace_dir, cleanup_containers):
    """[limits.disk] size sets the root device quota on a quota-capable pool,
    and is a hard error on a dir pool that cannot enforce it (#728)."""
    driver = _default_root_pool_driver()
    if driver is None:
        import pytest

        pytest.skip("could not resolve default root pool driver")

    container_name = calculate_container_name(workspace_dir, 1)
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[container]
persistent = true

[limits.disk]
size = "5GiB"
"""
    )

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "echo", "test"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
    )

    quota_capable = driver in ("btrfs", "zfs", "lvm", "ceph")
    if quota_capable:
        assert result.returncode == 0, (
            f"size quota should apply on a {driver} pool. stderr: {result.stderr}"
        )
        show = subprocess.run(
            ["incus", "config", "show", container_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert "size: 5GiB" in show.stdout, (
            f"root device should carry size=5GiB. Config: {show.stdout}"
        )
    else:
        assert result.returncode != 0, (
            f"size quota must be rejected on a {driver} pool that can't enforce it"
        )
        assert "quota-capable" in result.stderr, (
            f"error should explain the pool cannot enforce a quota. stderr: {result.stderr}"
        )
