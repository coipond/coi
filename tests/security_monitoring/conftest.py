"""Fixtures for the security-monitoring integration tests: each one writes a
monitoring config to ~/.coi/config.toml for the test and restores it after."""

import shutil
import uuid
from pathlib import Path

import pytest


@pytest.fixture
def test_workspace(tmp_path):
    """Create test workspace."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("# Test")
    return str(workspace)


@pytest.fixture
def disk_workspace():
    """Create a test workspace on a block device, for I/O threshold tests.

    pytest's tmp_path is under /tmp. Where /tmp is not on a block device (a
    tmpfs), a read from it, also with iflag=direct, never reaches a disk, so
    the cgroup's io.stat, which the I/O thresholds count, does not see it.
    The read tests failed on GitHub's ubuntu-24.04 runners on AWS and passed
    on those on Azure. The home directory is on the runner's disk.
    """
    workspace = Path.home() / ".cache" / "coi-test-workspaces" / uuid.uuid4().hex / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "README.md").write_text("# Test")
    yield str(workspace)
    shutil.rmtree(workspace.parent, ignore_errors=True)


@pytest.fixture
def enable_monitoring():
    """Enable monitoring for tests with high thresholds to avoid spurious alerts.

    Uses file_read_threshold_mb=500 to prevent container startup activity
    from triggering HIGH threats. Use enable_monitoring_low_thresholds
    for tests that specifically test threshold behavior.

    IMPORTANT: Includes [network] mode = "open" to prevent false positive
    network threats in CI environment.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )

    yield config_path

    if backup:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


@pytest.fixture
def enable_monitoring_defaults():
    """Enable monitoring with pause and kill on and every threshold at its
    default, as users run it. Open mode, as in enable_monitoring."""
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
"""
    )

    yield config_path

    if backup:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


@pytest.fixture
def enable_monitoring_high_read_threshold():
    """Enable monitoring with a HIGH file-read threshold (500MB) for the
    below-threshold negative test.

    Read detection compares a per-interval delta of the container's *whole-tree*
    cgroup read counter against the threshold, so background container I/O
    (dockerd/containerd/journald/apt) in the same poll interval is counted too.
    Against the default 50MB that background burst alone can cross the threshold
    and freeze the container regardless of how small the test's own read is —
    reducing the read from 49→30→10MB never stabilized it (#738). A 500MB
    threshold leaves headroom no plausible 1s interval of background reads can
    fill, so the negative assertion ("a sub-threshold read does not alert")
    becomes deterministic while still exercising the full read-accounting path.

    Includes [network] mode = "open" to avoid false-positive network threats.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 10000
"""
    )

    yield config_path

    if backup:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


@pytest.fixture
def enable_monitoring_metadata_open():
    """Enable monitoring as enable_monitoring does, with
    block_metadata_endpoint = false.

    Open mode rejects 169.254.0.0/16 by default: the reject answers curl with a
    TCP reset at once, so no socket is left for the process monitor to see. A
    test that needs a live connection to the metadata endpoint uses this.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"
block_metadata_endpoint = false

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )

    yield config_path

    if backup:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


@pytest.fixture
def enable_monitoring_oneliner_warn():
    """Enable monitoring with reverse_shell_one_liners = "warn" (#842).

    Downgrades the interpreter one-liner reverse-shell class to WARNING (audited,
    never kills), while auto_kill_on_critical stays on for the unambiguous class.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
reverse_shell_one_liners = "warn"
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )

    yield config_path

    if backup:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


@pytest.fixture
def enable_monitoring_low_thresholds():
    """Enable monitoring with default low thresholds for threshold-specific tests.

    Uses file_read_threshold_mb=50 (default) so tests can verify threshold behavior.

    IMPORTANT: Includes [network] mode = "open" to prevent false positive
    network threats in CI environment.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 50
file_read_rate_mb_per_sec = 1000
"""
    )

    yield config_path

    if backup:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


@pytest.fixture
def enable_monitoring_forensics():
    """Monitoring with auto-kill AND forensics_on_kill enabled (opt-in) — the
    kill must leave a forensic copy behind."""
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
forensics_on_kill = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )

    yield config_path

    if backup:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


@pytest.fixture
def enable_monitoring_small_tmp():
    """Enable monitoring with a small RAM-backed /tmp (64MiB).

    The low-disk-space warning fires above 80% /tmp usage; a 64MiB tmpfs
    ([limits.disk] tmpfs_size) can be filled past that in about a second.
    A high read threshold (writes share it) keeps the fill from raising
    other threats.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[limits.disk]
tmpfs_size = "64MiB"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )

    yield config_path

    if backup:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()
