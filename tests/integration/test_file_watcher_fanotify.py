"""
Integration tests for FileWatcher fanotify-based sensitive file monitoring.

These tests verify that the host-side fanotify watcher detects:
- Reads of credential files (/etc/shadow) — detected via FAN_OPEN after the
  30-second startup grace period expires.
- Writes to persistence-relevant files (/etc/sudoers, root authorized_keys) —
  detected via FAN_CLOSE_WRITE once the file is marked. A file replaced on
  its first write (overlayfs copy-up) or created after the start is marked by
  the 30-second backstop re-mark cycle.
- Writes to the code user's persistence and credential files (~/.bashrc,
  ~/.profile, ~/.ssh/authorized_keys, the user crontab, the tool credential
  file) — created, written or renamed over — detected by the directory
  watcher; coi's own copy and host-side pushes are not flagged.

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
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from support.helpers import exec_as_code_user
from support.monitoring import (
    coi_session_logs,
    get_threat_events,
    monitored_shell,
    wait_for_threats,
)

# Grace period (30 s) + a backstop cycle (30 s) + margin.
_DETECT_DEADLINE = 90
# Long enough for a read to land after the grace period and one backstop.
_GRACE_AND_BACKSTOP = 70


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

    def test_sudo_shadow_read_not_flagged(self, coi_binary, tmp_path, _monitoring_enabled):
        """sudo by the code user raises no /etc/shadow read threat; cat does.

        sudo (PAM) opens /etc/shadow on every use. The watcher skips that read
        by the reader's /proc/<pid>/exe, which the host must resolve to the
        container path of sudo. sudo runs every 3 s past the grace period and
        a backstop cycle with no read threat; then a read by cat is detected,
        so the watcher was live while sudo ran.
        """
        workspace = str(tmp_path / "workspace")
        os.makedirs(workspace, exist_ok=True)
        container_name = _container_name(workspace, 74)

        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", workspace, "--slot", "74"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        def is_shadow_read(e):
            return (
                _sensitive_file(e).get("path") == "etc/shadow"
                and _sensitive_file(e).get("access") == "read"
            )

        try:
            if not _wait_running(container_name):
                pytest.fail(f"Container {container_name} did not start")

            sudo_ok = 0
            deadline = time.monotonic() + _GRACE_AND_BACKSTOP
            while time.monotonic() < deadline:
                result = subprocess.run(
                    ["incus", "exec", container_name, "--user", "1000", "--", "sudo", "-n", "true"],
                    capture_output=True,
                    timeout=15,
                )
                sudo_ok += result.returncode == 0
                flagged = [e for e in _get_threat_events(container_name) if is_shadow_read(e)]
                assert not flagged, f"sudo's /etc/shadow read was flagged: {flagged}"
                time.sleep(3)
            assert sudo_ok, f"`sudo -n true` never succeeded as uid 1000: {result.stderr!r}"

            threats = _trigger_until_detected(
                container_name, "cat /etc/shadow > /dev/null", is_shadow_read
            )
            assert threats, (
                "No /etc/shadow read threat for cat either, so the watcher was not "
                f"live while sudo ran. Events: {_get_threat_events(container_name)}"
                f"{coi_session_logs(container_name)}"
            )
        finally:
            proc.terminate()
            _cleanup(container_name, coi_binary)


# ── code user persistence and credential files ──────────────────────────────

_CREDENTIALS = "home/code/.claude/.credentials.json"

# Grace period (30 s) + one backstop cycle (30 s) + margin.
_MAX_WAIT = 90


@pytest.fixture
def host_credentials():
    """A host ~/.claude/.credentials.json for coi to copy; restored after."""
    claude_dir = Path.home() / ".claude"
    cred = claude_dir / ".credentials.json"
    existed = claude_dir.exists()
    backup = cred.read_bytes() if cred.exists() else None
    claude_dir.mkdir(exist_ok=True)
    cred.write_text('{"claudeAiOauth": {"accessToken": "e2e-host-token"}}')
    yield cred
    if backup is not None:
        cred.write_bytes(backup)
    elif not existed:
        shutil.rmtree(claude_dir)
    else:
        cred.unlink()


def _is_write_to(rel):
    """A threat for a write to the container-relative file rel."""
    return lambda e: (e.get("evidence", {}).get("sensitive_file") or {}).get("path") == rel


def _repeat_until_flagged(container_name, rel, write):
    """Repeat write on each poll until a threat for rel is logged; return it.

    write returns a CompletedProcess or an exit code; a write that fails is
    an error here, not a missing threat."""

    def checked_write():
        r = write()
        rc = r if isinstance(r, int) else r.returncode
        assert rc == 0, f"the write to {rel} failed ({rc}): {getattr(r, 'stderr', '')}"

    found = wait_for_threats(
        container_name, _is_write_to(rel), max_wait=_MAX_WAIT, action=checked_write
    )
    assert found, (
        f"no threat for a write to {rel} within {_MAX_WAIT} s; threat events: "
        f"{get_threat_events(container_name)}{coi_session_logs(container_name)}"
    )
    return found[0]


def test_user_persistence_and_credential_writes_flagged(
    coi_binary, workspace_dir, host_credentials, tmp_path
):
    """A container write to each code user file raises HIGH; coi's copy at
    session start and a host-side `coi file push` raise nothing. Each write
    repeats on each poll (2 s) until its threat is logged: the watcher ignores the
    first 30 s, and a directory missing at the mark pass is marked when
    created or by the 30 s backstop."""
    with monitored_shell(workspace_dir, coi_binary, 7, _MONITORING_CONFIG) as (container_name, _):
        copied = exec_as_code_user(container_name, "cat", "/home/code/.claude/.credentials.json")
        assert "e2e-host-token" in copied.stdout, (
            f"coi did not copy the credential file: {copied.stdout}{copied.stderr}"
        )

        bashrc = _repeat_until_flagged(
            container_name,
            "home/code/.bashrc",
            lambda: exec_as_code_user(container_name, "sh", "-c", "echo '# e2e' >> ~/.bashrc"),
        )

        # The monitor is past its grace period: a host-side push now is seen.
        pushed = tmp_path / "pushed.json"
        pushed.write_text('{"claudeAiOauth": {"accessToken": "e2e-pushed-token"}}')
        result = subprocess.run(
            [coi_binary, "file", "push", str(pushed), f"{container_name}:/{_CREDENTIALS}"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, f"coi file push failed: {result.stdout}{result.stderr}"

        # Renamed over. The watcher handles events in order: once this threat
        # is logged, a threat for the push above would be logged too.
        profile = _repeat_until_flagged(
            container_name,
            "home/code/.profile",
            lambda: exec_as_code_user(
                container_name,
                "sh",
                "-c",
                "{ cat ~/.profile 2>/dev/null; echo '# e2e'; } > ~/.profile.new"
                " && mv ~/.profile.new ~/.profile",
            ),
        )
        cred_threats = [
            e for e in get_threat_events(container_name) if _is_write_to(_CREDENTIALS)(e)
        ]
        assert not cred_threats, (
            f"coi's copy or a host-side push of the credential file raised a threat: {cred_threats}"
        )

        authorized_keys = _repeat_until_flagged(
            container_name,
            "home/code/.ssh/authorized_keys",
            lambda: exec_as_code_user(
                container_name,
                "sh",
                "-c",
                "mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAA e2e' >> ~/.ssh/authorized_keys",
            ),
        )
        crontab = _repeat_until_flagged(
            container_name,
            "var/spool/cron/crontabs/code",
            lambda: _incus_exec(
                container_name,
                "mkdir -p /var/spool/cron/crontabs"
                " && echo '* * * * * true' >> /var/spool/cron/crontabs/code",
            ),
        )
        # As root: the push above gave the file the host user's uid, which
        # is not the code user's on a host whose uid is not 1000.
        credentials = _repeat_until_flagged(
            container_name,
            _CREDENTIALS,
            lambda: _incus_exec(
                container_name,
                f"echo '{{\"claudeAiOauth\": {{}}}}' > /{_CREDENTIALS}",
            ),
        )

        for event in (bashrc, profile, authorized_keys, crontab, credentials):
            assert event["level"] == "high", event
            assert event["evidence"]["sensitive_file"]["access"] == "write", event
        assert credentials["category"] == "credential_access", credentials
        assert bashrc["category"] == "persistence", bashrc
