"""
Integration tests for FileWatcher fanotify-based sensitive file monitoring.

These tests verify that the host-side fanotify watcher detects:
- Reads of credential files (/etc/shadow) — detected via FAN_OPEN after the
  30-second startup grace period expires.
- Writes to persistence-relevant files (/etc/sudoers, root authorized_keys) —
  detected after the grace period AND a backstop re-mark cycle, because overlayfs
  copy-up replaces the inode on the first write to a lower-layer file.

All access is performed via `incus exec` so the monitor daemon (which runs as
a host-side process) sees the event from outside the container.

Timing note: the FileWatcher suppresses all events for 30 seconds after the
container's init PID is first resolved. This prevents false positives from
system daemons (PAM, sshd, cron) that legitimately access sensitive files
during container boot. Tests that check FAN_OPEN on /etc/shadow must therefore
wait at least 35 seconds (30 s grace + margin) before triggering the access.
Write-detection tests require both the grace period and a backstop cycle (~65 s
total: 5 s init + 30 s grace/backstop + write + poll).
"""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

# ── helpers ──────────────────────────────────────────────────────────────────


def _container_name(workspace: str, slot: int) -> str:
    abs_path = os.path.abspath(workspace)
    digest = hashlib.sha256(abs_path.encode()).hexdigest()[:8]
    return f"coi-{digest}-{slot}"


def _wait_running(name: str, timeout: int = 60) -> bool:
    for _ in range(timeout):
        result = subprocess.run(
            ["incus", "list", name, "--format=json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            containers = json.loads(result.stdout)
            if containers and containers[0].get("status") == "Running":
                return True
        time.sleep(1)
    return False


def _get_threat_events(container_name: str) -> list[dict]:
    audit_file = Path.home() / ".coi" / "audit" / f"{container_name}.jsonl"
    if not audit_file.exists():
        return []
    events = []
    with audit_file.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    event = json.loads(line)
                    if "level" in event:
                        events.append(event)
                except json.JSONDecodeError:
                    pass
    return events


def _poll_file_threats(
    container_name: str,
    max_wait: int,
    predicate,
) -> list[dict]:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        events = _get_threat_events(container_name)
        matched = [e for e in events if predicate(e)]
        if matched:
            return matched
        time.sleep(1)
    return []


def _cleanup(name: str, coi_binary: str) -> None:
    subprocess.run(
        [coi_binary, "container", "delete", name, "--force"],
        timeout=30,
        check=False,
    )


def _incus_exec(container_name: str, cmd: str) -> int:
    result = subprocess.run(
        ["incus", "exec", container_name, "--", "bash", "-c", cmd],
        capture_output=True,
        timeout=15,
    )
    return result.returncode


# ── shared config ─────────────────────────────────────────────────────────────

_MONITORING_CONFIG = """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 2
file_read_threshold_mb = 100000.0
file_read_rate_mb_per_sec = 100000.0
audit_log_retention_days = 30
"""


@pytest.fixture
def _monitoring_enabled():
    """Write monitoring config to ~/.coi/config.toml and restore on teardown."""
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_MONITORING_CONFIG)
    yield
    if backup is not None:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


# ── tests ─────────────────────────────────────────────────────────────────────


class TestFileWatcherFanotify:
    """Host-side fanotify sensitive file monitoring integration tests."""

    def test_shadow_read_detected(self, coi_binary, tmp_path, _monitoring_enabled):
        """Reading /etc/shadow inside the container raises a HIGH credential_access threat.

        The shadow file exists on the lower overlayfs layer from the container
        image. A read (cat) does not trigger copy-up so the fanotify mark placed
        on the original inode fires via FAN_OPEN.

        The FileWatcher suppresses all events for 30 seconds after the container's
        init PID is first resolved, to avoid false positives from system daemons
        (PAM, sshd, cron) that access /etc/shadow during normal container boot.
        The test therefore waits 35 seconds before triggering the read so the
        access falls outside the grace window.
        """
        workspace = str(tmp_path / "workspace")
        os.makedirs(workspace, exist_ok=True)
        container_name = _container_name(workspace, 71)

        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", workspace, "--slot", "71"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            if not _wait_running(container_name):
                pytest.fail(f"Container {container_name} did not start")

            # Wait for: daemon init (5 s) + 30 s grace period + 2 s safety margin.
            # Reads during the grace window are silently dropped to avoid triggering
            # auto-pause from legitimate system-daemon accesses at boot.
            time.sleep(37)

            # Ensure /etc/shadow exists inside the container before reading.
            # Minimal images may not ship it; create a stub if absent.
            _incus_exec(
                container_name,
                "[ -f /etc/shadow ] || (touch /etc/shadow && chmod 640 /etc/shadow)",
            )

            # Read /etc/shadow — triggers FAN_OPEN on the inode.
            _incus_exec(container_name, "cat /etc/shadow > /dev/null 2>&1 || true")

            threats = _poll_file_threats(
                container_name,
                max_wait=15,
                predicate=lambda e: (
                    e.get("category") == "credential_access"
                    and e.get("level") == "high"
                    and "shadow" in e.get("evidence", {}).get("sensitive_file", {}).get("path", "")
                    and e.get("evidence", {}).get("sensitive_file", {}).get("access") == "read"
                ),
            )

            assert len(threats) > 0, (
                f"Expected HIGH credential_access threat for /etc/shadow read. "
                f"Events: {_get_threat_events(container_name)}"
            )
        finally:
            proc.terminate()
            _cleanup(container_name, coi_binary)

    def test_sudoers_write_detected(self, coi_binary, tmp_path, _monitoring_enabled):
        """Writing to /etc/sudoers raises a CRITICAL persistence threat.

        The first write to /etc/sudoers triggers overlayfs copy-up, moving the
        file to the upper layer with a new inode. The FileWatcher's 30-second
        backstop then re-marks the new inode. A second write (after both the
        backstop and the 30-second startup grace period) is detected.

        Timing: ~55 s total (5 s init + first write + 35 s wait covering both
        grace period and backstop + second write + 15 s poll).
        """
        workspace = str(tmp_path / "workspace")
        os.makedirs(workspace, exist_ok=True)
        container_name = _container_name(workspace, 72)

        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", workspace, "--slot", "72"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            if not _wait_running(container_name):
                pytest.fail(f"Container {container_name} did not start")

            time.sleep(5)

            # Ensure /etc/sudoers exists before the test.
            _incus_exec(
                container_name,
                "[ -f /etc/sudoers ] || touch /etc/sudoers",
            )

            # First write: triggers overlayfs copy-up → new inode (current mark misses it).
            _incus_exec(
                container_name,
                "echo '# coi-test' >> /etc/sudoers",
            )

            # Wait for the backstop ticker to re-mark the new inode (≤30 s + margin).
            time.sleep(35)

            # Second write: now on the upper-layer inode — fanotify detects it.
            _incus_exec(
                container_name,
                "echo '# coi-test-2' >> /etc/sudoers",
            )

            threats = _poll_file_threats(
                container_name,
                max_wait=15,
                predicate=lambda e: (
                    e.get("category") == "persistence"
                    and e.get("level") == "critical"
                    and "sudoers" in e.get("evidence", {}).get("sensitive_file", {}).get("path", "")
                    and e.get("evidence", {}).get("sensitive_file", {}).get("access") == "write"
                ),
            )

            assert len(threats) > 0, (
                f"Expected CRITICAL persistence threat for /etc/sudoers write. "
                f"Events: {_get_threat_events(container_name)}"
            )
        finally:
            proc.terminate()
            _cleanup(container_name, coi_binary)

    def test_authorized_keys_write_detected(self, coi_binary, tmp_path, _monitoring_enabled):
        """Writing to /root/.ssh/authorized_keys raises a CRITICAL persistence threat.

        authorized_keys typically does not exist in a fresh container image, so
        the initial mark attempt is silently skipped (ENOENT). The first write
        creates the file in the overlayfs upper layer. After the 30-second backstop
        (and grace period) the new inode is marked. A second write triggers detection.
        """
        workspace = str(tmp_path / "workspace")
        os.makedirs(workspace, exist_ok=True)
        container_name = _container_name(workspace, 73)

        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", workspace, "--slot", "73"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            if not _wait_running(container_name):
                pytest.fail(f"Container {container_name} did not start")

            time.sleep(5)

            # First write: creates the file on the upper layer (initial mark was absent).
            _incus_exec(
                container_name,
                "mkdir -p /root/.ssh && echo 'ssh-rsa AAAAB3N coi-test' > /root/.ssh/authorized_keys",
            )

            # Wait for the backstop to mark the newly created file.
            time.sleep(35)

            # Second write: the file's inode is now in the map — detected.
            _incus_exec(
                container_name,
                "echo 'ssh-rsa AAAAB3N coi-test-2' >> /root/.ssh/authorized_keys",
            )

            threats = _poll_file_threats(
                container_name,
                max_wait=15,
                predicate=lambda e: (
                    e.get("category") == "persistence"
                    and e.get("level") == "critical"
                    and "authorized_keys"
                    in e.get("evidence", {}).get("sensitive_file", {}).get("path", "")
                    and e.get("evidence", {}).get("sensitive_file", {}).get("access") == "write"
                ),
            )

            assert len(threats) > 0, (
                f"Expected CRITICAL persistence threat for authorized_keys write. "
                f"Events: {_get_threat_events(container_name)}"
            )
        finally:
            proc.terminate()
            _cleanup(container_name, coi_binary)
