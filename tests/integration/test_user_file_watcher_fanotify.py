"""
Test for coi shell - the security monitor flags writes to the code user's
persistence and credential files.

Tests that:
1. coi's own copy of the tool credential file at session start raises no
   threat;
2. a write from the host through the Incus file API (`coi file push`, the
   path coi's copy takes) raises no threat while the monitor runs;
3. a write in the container to ~/.bashrc, ~/.profile (renamed over),
   ~/.ssh/authorized_keys (created), the user crontab and
   ~/.claude/.credentials.json raises a HIGH threat naming the file.

Flow:
- create ~/.claude/.credentials.json on the host, start a monitored shell
  (auto-pause off, so one session sees every write);
- repeat each write every 3 s until its threat is in the audit log: the
  watcher ignores the first 30 s (boot grace period), and a directory that
  does not exist at the mark pass is marked when created or by the 30 s
  backstop.
"""

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from support.helpers import exec_as_code_user
from support.monitoring import coi_session_logs, get_threat_events, monitored_shell

_CONFIG = """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 2
file_read_threshold_mb = 100000.0
file_read_rate_mb_per_sec = 100000.0
"""

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


def _write_threats(container_name, rel):
    return [
        e
        for e in get_threat_events(container_name)
        if (e.get("evidence", {}).get("sensitive_file") or {}).get("path") == rel
    ]


def _root(container_name, cmd):
    subprocess.run(
        ["incus", "exec", container_name, "--", "sh", "-c", cmd],
        capture_output=True,
        timeout=30,
    )


def _repeat_until_flagged(container_name, rel, write):
    """Run write every 3 s until a threat for rel is logged; return it."""
    deadline = time.monotonic() + _MAX_WAIT
    while time.monotonic() < deadline:
        write()
        found = _write_threats(container_name, rel)
        if found:
            return found[0]
        time.sleep(3)
    found = _write_threats(container_name, rel)
    assert found, (
        f"no threat for a write to {rel} within {_MAX_WAIT} s; threat events: "
        f"{get_threat_events(container_name)}{coi_session_logs(container_name)}"
    )
    return found[0]


def test_user_persistence_and_credential_writes_flagged(
    coi_binary, workspace_dir, host_credentials, tmp_path
):
    with monitored_shell(workspace_dir, coi_binary, 7, _CONFIG) as (container_name, _):
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
        assert not _write_threats(container_name, _CREDENTIALS), (
            "coi's copy or a host-side push of the credential file raised a threat: "
            f"{_write_threats(container_name, _CREDENTIALS)}"
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
            lambda: _root(
                container_name,
                "mkdir -p /var/spool/cron/crontabs"
                " && echo '* * * * * true' >> /var/spool/cron/crontabs/code",
            ),
        )
        credentials = _repeat_until_flagged(
            container_name,
            _CREDENTIALS,
            lambda: exec_as_code_user(
                container_name,
                "sh",
                "-c",
                "echo '{\"claudeAiOauth\": {}}' > ~/.claude/.credentials.json",
            ),
        )

        for event in (bashrc, profile, authorized_keys, crontab, credentials):
            assert event["level"] == "high", event
            assert event["evidence"]["sensitive_file"]["access"] == "write", event
        assert credentials["category"] == "credential_access", credentials
        assert bashrc["category"] == "persistence", bashrc
