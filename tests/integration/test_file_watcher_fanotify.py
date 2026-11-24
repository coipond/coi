"""
Integration tests for FileWatcher fanotify-based sensitive file monitoring.

These tests verify that the host-side fanotify watcher detects:
- Reads of credential files (/etc/shadow) — detected via FAN_OPEN after the
  30-second startup grace period expires.
- Writes to persistence-relevant files (/etc/sudoers, root authorized_keys) —
  detected via FAN_CLOSE_WRITE once the file is marked. A file replaced on
  its first write (overlayfs copy-up) or created after the start is marked by
  the 30-second backstop re-mark cycle.

All access is performed via `incus exec` so the monitor daemon (which runs as
a host-side process) sees the event from outside the container.

Timing note: the FileWatcher suppresses all events for 30 seconds after the
container's init PID is first resolved, to avoid false positives from system
daemons (PAM, sshd, cron) that access sensitive files during container boot.
Each test repeats its access every few seconds until the threat appears, and
fails once a deadline covering the grace period and a backstop cycle passes.

The watcher needs CAP_SYS_ADMIN (fanotify_init), CAP_SYS_PTRACE (paths under
/proc/<pid>/root) and CAP_DAC_READ_SEARCH (marking and opening root-only
files). The CI lane grants them to the coi binary with setcap; without them
the session log says "sensitive file monitoring disabled" and these tests fail.
"""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import coi_session_logs

# Grace period (30 s) + a backstop cycle (30 s) + margin.
_DETECT_DEADLINE = 90


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


def _trigger_until_detected(container_name: str, cmd: str, predicate) -> list[dict]:
    """Run cmd in the container every 3 s until a threat event matches
    predicate or _DETECT_DEADLINE seconds pass. Returns the matching events."""
    deadline = time.monotonic() + _DETECT_DEADLINE
    while time.monotonic() < deadline:
        _incus_exec(container_name, cmd)
        for _ in range(3):
            matched = [e for e in _get_threat_events(container_name) if predicate(e)]
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


def _sensitive_file(event: dict) -> dict:
    return event.get("evidence", {}).get("sensitive_file") or {}


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

        The shadow file exists in the container image, so the initial mark
        pass marks it and a read (cat) fires FAN_OPEN. Reads during the 30 s
        startup grace period are dropped; the read repeats until one lands
        after it.
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

            assert _incus_exec(container_name, "test -f /etc/shadow") == 0, (
                "/etc/shadow is missing from the container image"
            )

            threats = _trigger_until_detected(
                container_name,
                "cat /etc/shadow > /dev/null",
                lambda e: (
                    e.get("category") == "credential_access"
                    and e.get("level") == "high"
                    and "shadow" in _sensitive_file(e).get("path", "")
                    and _sensitive_file(e).get("access") == "read"
                ),
            )

            assert threats, (
                f"No HIGH credential_access threat for an /etc/shadow read within "
                f"{_DETECT_DEADLINE}s. Events: {_get_threat_events(container_name)}"
                f"{coi_session_logs(container_name)}"
            )
        finally:
            proc.terminate()
            _cleanup(container_name, coi_binary)

    def test_sudoers_write_detected(self, coi_binary, tmp_path, _monitoring_enabled):
        """Writing to /etc/sudoers raises a CRITICAL persistence threat.

        Where the first write replaces the inode (overlayfs copy-up), the
        backstop marks the new one within 30 s; the write repeats until one is
        detected.
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

            threats = _trigger_until_detected(
                container_name,
                "echo '# coi-test' >> /etc/sudoers",
                lambda e: (
                    e.get("category") == "persistence"
                    and e.get("level") == "critical"
                    and "sudoers" in _sensitive_file(e).get("path", "")
                    and _sensitive_file(e).get("access") == "write"
                ),
            )

            assert threats, (
                f"No CRITICAL persistence threat for an /etc/sudoers write within "
                f"{_DETECT_DEADLINE}s. Events: {_get_threat_events(container_name)}"
                f"{coi_session_logs(container_name)}"
            )
        finally:
            proc.terminate()
            _cleanup(container_name, coi_binary)

    def test_authorized_keys_write_detected(self, coi_binary, tmp_path, _monitoring_enabled):
        """Writing to /root/.ssh/authorized_keys raises a CRITICAL persistence threat.

        authorized_keys does not exist in a fresh container, so the initial
        mark pass skips it. The first write creates it, the backstop marks it
        within 30 s, and the write repeats until one is detected.
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

            threats = _trigger_until_detected(
                container_name,
                "mkdir -p /root/.ssh && echo 'ssh-rsa AAAAB3N coi-test' >> /root/.ssh/authorized_keys",
                lambda e: (
                    e.get("category") == "persistence"
                    and e.get("level") == "critical"
                    and "authorized_keys" in _sensitive_file(e).get("path", "")
                    and _sensitive_file(e).get("access") == "write"
                ),
            )

            assert threats, (
                f"No CRITICAL persistence threat for an authorized_keys write within "
                f"{_DETECT_DEADLINE}s. Events: {_get_threat_events(container_name)}"
                f"{coi_session_logs(container_name)}"
            )
        finally:
            proc.terminate()
            _cleanup(container_name, coi_binary)
