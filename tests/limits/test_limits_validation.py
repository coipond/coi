"""
Test limits validation.

Tests that:
1. A valid limit is accepted and applied end to end (ONE boot per limit family)
2. An invalid limit is rejected with a clear error before container launch
3. Incus itself accepts every disk I/O format class we validate (no boot needed)

The format MATRICES (every valid/invalid string shape) live in Go unit tests
on the validators: internal/limits/validator_test.go. Booting a container per
format string proved nothing the unit tests don't, cost minutes of CI time,
and — for pathological values like a 100kB/s disk read throttle — flaked on
the host page cache (see #583). Each e2e test here boots at most one
container with a representative value to prove the config-to-container
pipeline, and each invalid test asserts one representative rejection.
"""

import subprocess
from pathlib import Path

from support.helpers import calculate_container_name


def run_coi_with_limits(coi_binary, workspace_dir, limits_toml, timeout=120):
    """Write a [limits.*] config into the workspace and run `coi run echo test`."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(limits_toml)

    return subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "echo", "test"],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=workspace_dir,
    )


def test_valid_cpu_count_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that a valid CPU count boots and applies end to end."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.cpu]
count = "0-1,3"
""",
    )
    assert result.returncode == 0, f"CPU count '0-1,3' should be valid. stderr: {result.stderr}"


def test_invalid_cpu_count_rejected(coi_binary, workspace_dir):
    """Test that an invalid CPU count is rejected before launch."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.cpu]
count = "a-b"
""",
        timeout=30,
    )
    assert result.returncode != 0, "CPU count 'a-b' should be invalid"
    assert "invalid" in result.stderr.lower() or "validation" in result.stderr.lower(), (
        f"Error message should indicate validation failure. stderr: {result.stderr}"
    )


def test_valid_memory_limit_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that a valid memory limit boots and applies end to end."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.memory]
limit = "512MiB"
""",
    )
    assert result.returncode == 0, f"Memory '512MiB' should be valid. stderr: {result.stderr}"


def test_invalid_memory_limit_rejected(coi_binary, workspace_dir):
    """Test that an invalid memory limit is rejected before launch."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.memory]
limit = "2XB"
""",
        timeout=30,
    )
    assert result.returncode != 0, "Memory '2XB' should be invalid"
    assert "invalid" in result.stderr.lower() or "validation" in result.stderr.lower(), (
        f"Error message should indicate validation failure. stderr: {result.stderr}"
    )


def test_valid_cpu_allowance_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that a valid CPU allowance boots and applies end to end."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.cpu]
allowance = "25ms/100ms"
""",
    )
    assert result.returncode == 0, (
        f"CPU allowance '25ms/100ms' should be valid. stderr: {result.stderr}"
    )


def test_invalid_cpu_allowance_rejected(coi_binary, workspace_dir):
    """Test that an invalid CPU allowance is rejected before launch."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.cpu]
allowance = "25/100"
""",
        timeout=30,
    )
    assert result.returncode != 0, "CPU allowance '25/100' should be invalid"
    assert "invalid" in result.stderr.lower() or "validation" in result.stderr.lower(), (
        f"Error message should indicate validation failure. stderr: {result.stderr}"
    )


def test_valid_disk_io_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that a valid disk I/O limit is accepted and applied end to end.

    One boot with a generous limit only: booting with a pathological rate like
    100kB applies the throttle to the container's root disk BEFORE the
    readiness wait, so boot only completes in time when the host page cache
    absorbs the I/O — a recurring CI flake, not a validation check (#583).
    Incus-side acceptance of the other format classes is covered boot-free by
    test_incus_accepts_disk_io_formats below.
    """
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.disk]
read = "10MB"
""",
    )
    assert result.returncode == 0, (
        f"Disk I/O '10MB' should be valid and bootable. stderr: {result.stderr}"
    )


def test_incus_accepts_disk_io_formats(coi_binary, workspace_dir, cleanup_containers):
    """Test that Incus itself accepts every disk I/O format class we validate.

    Coi's validator is a regex; the real arbiter is Incus's units parser at
    `incus config device set root limits.read=...`. Setting the key on a
    STOPPED container still runs Incus's value validation, so this proves
    SI (kB), IEC-free sizes (GB) and iops acceptance without booting anything
    — and without throttling a boot.
    """
    container_name = calculate_container_name(workspace_dir, 2)

    result = subprocess.run(
        ["incus", "init", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"incus init should succeed. stderr: {result.stderr}"

    try:
        # Ensure the root disk is an instance-local device so its keys are
        # settable (mirrors ensureInstanceRootDevice in internal/limits).
        # Ignore failure: it errors if root is already instance-local.
        subprocess.run(
            ["incus", "config", "device", "override", container_name, "root"],
            capture_output=True,
            timeout=30,
        )

        for io_rate in ["10MB", "100kB", "1GB", "1000iops"]:
            result = subprocess.run(
                [
                    "incus",
                    "config",
                    "device",
                    "set",
                    container_name,
                    "root",
                    f"limits.read={io_rate}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Incus should accept limits.read={io_rate}. stderr: {result.stderr}"
            )
    finally:
        subprocess.run(
            ["incus", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )


def test_invalid_disk_io_rejected(coi_binary, workspace_dir):
    """Test that an invalid disk I/O rate is rejected before launch."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.disk]
read = "10MB/s"
""",
        timeout=30,
    )
    assert result.returncode != 0, "Disk I/O '10MB/s' should be invalid"
    assert "invalid" in result.stderr.lower() or "validation" in result.stderr.lower(), (
        f"Error message should indicate validation failure. stderr: {result.stderr}"
    )


def test_valid_duration_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that a valid max_duration boots and applies end to end."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.runtime]
max_duration = "1h30m"
""",
    )
    assert result.returncode == 0, f"Duration '1h30m' should be valid. stderr: {result.stderr}"


def test_invalid_duration_rejected(coi_binary, workspace_dir):
    """Test that an invalid max_duration is rejected before launch."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.runtime]
max_duration = "2x"
""",
        timeout=30,
    )
    assert result.returncode != 0, "Duration '2x' should be invalid"
    assert "invalid" in result.stderr.lower() or "validation" in result.stderr.lower(), (
        f"Error message should indicate validation failure. stderr: {result.stderr}"
    )


def test_valid_priority_applied(coi_binary, workspace_dir, cleanup_containers):
    """Test that a valid priority boots and applies end to end."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.cpu]
priority = 5
""",
    )
    assert result.returncode == 0, f"Priority 5 should be valid. stderr: {result.stderr}"


def test_invalid_priority_rejected(coi_binary, workspace_dir):
    """Test that an out-of-range priority is rejected before launch."""
    result = run_coi_with_limits(
        coi_binary,
        workspace_dir,
        """
[limits.cpu]
priority = 11
""",
        timeout=30,
    )
    assert result.returncode != 0, "Priority 11 should be invalid"
    assert "invalid" in result.stderr.lower() or "priority" in result.stderr.lower(), (
        f"Error message should indicate priority validation failure. stderr: {result.stderr}"
    )
