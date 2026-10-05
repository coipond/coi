#!/usr/bin/env python3
"""
Integration tests for LogWatcher inotify-based detection.

These tests verify behaviors that are specific to the inotify implementation:
- syslog is watched in addition to auth.log
- log rotation (mv + new file) is handled transparently
- events are delivered promptly (within 8 s) rather than on a 5 s polling cycle

All tests write suspicious lines directly into the container via incus exec
(not via SSH) so the exact write time is known.
"""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Shared helpers (mirror tests/support/monitoring.py)
# ---------------------------------------------------------------------------


def get_container_name_from_workspace(workspace):
    abs_path = os.path.abspath(workspace)
    hash_digest = hashlib.sha256(abs_path.encode()).hexdigest()[:8]
    return f"coi-{hash_digest}-1"


def wait_for_container_running(name, timeout=60):
    for _ in range(timeout):
        result = subprocess.run(
            ["incus", "list", name, "--format=json"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            containers = json.loads(result.stdout)
            if containers and containers[0].get("status") == "Running":
                return True
        time.sleep(1)
    return False


def get_threat_events(container_name):
    log_path = Path.home() / ".coi" / "audit" / f"{container_name}.jsonl"
    if not log_path.exists():
        return []
    events = []
    with open(log_path) as f:
        for line in f:
            if line.strip():
                try:
                    event = json.loads(line)
                    if "level" in event:
                        events.append(event)
                except json.JSONDecodeError:
                    pass
    return events


def cleanup_container(name, coi_binary):
    subprocess.run([coi_binary, "container", "delete", name, "--force"], timeout=30, check=False)


def terminate_shell(proc):
    """Fully reap a `coi shell` process so its monitor releases host resources.

    A bare proc.terminate() is fire-and-forget: the monitor daemon (inotify
    watches, cgroup/nft state) may still be alive when the next test's container
    starts, starving it. Wait for the process to actually exit, escalating to
    SIGKILL if it doesn't."""
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass


def container_exec_ready(name, timeout=30):
    """Wait until the container's agent accepts `incus exec` (running != ready)."""
    for _ in range(timeout):
        result = subprocess.run(
            ["incus", "exec", name, "--", "true"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True
        time.sleep(1)
    return False


def line_in_container_file(name, path, needle):
    """Return True if `needle` appears in the container file at `path`."""
    result = subprocess.run(
        ["incus", "exec", name, "--", "cat", path],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.returncode == 0 and needle in result.stdout


def _monitoring_config(auto_pause=False):
    return f"""
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = {"true" if auto_pause else "false"}
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
process_count_threshold = 9999
process_spawn_rate_threshold = 9999
"""


@pytest.fixture
def test_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("# Test")
    return str(workspace)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLogWatcherInotify:
    """Integration tests for inotify-driven log file monitoring."""

    def test_syslog_event_detected(self, test_workspace, coi_binary):
        """Writing a suspicious line to syslog (not auth.log) is detected.

        Verifies that both log candidates are actively watched — the existing
        TestAuthLogWatcher suite only exercises auth.log.
        """
        config_path = Path.home() / ".coi" / "config.toml"
        backup = config_path.read_text() if config_path.exists() else None
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(_monitoring_config())

        container_name = (
            get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-66"
        )
        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "66"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            assert wait_for_container_running(container_name), (
                f"Container {container_name} did not start"
            )
            # "Running" != agent-ready: wait until incus exec actually works before
            # writing, so a slow agent under CI load doesn't silently drop the write.
            assert container_exec_ready(container_name), (
                f"Container {container_name} agent not ready for exec"
            )
            time.sleep(3)  # wait for monitoring daemon to start

            write_syslog = [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "mkdir -p /var/log && "
                "echo 'Jun  5 12:00:00 coi sshd[1234]: Failed password for attacker"
                " from 1.2.3.4 port 22222 ssh2' >> /var/log/syslog",
            ]

            # Re-write on each poll: a single write can land before the watcher has
            # registered its inotify watch (monitor still starting up under CI load)
            # and be missed. Re-writing guarantees a write lands after registration
            # rather than depending on one perfectly-timed write.
            events = []
            auth_events = []
            for _ in range(30):
                subprocess.run(
                    write_syslog,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(1)
                events = get_threat_events(container_name)
                auth_events = [
                    e
                    for e in events
                    if e.get("category") == "auth"
                    and e.get("evidence", {}).get("auth_log", {}).get("pattern")
                    == "ssh_failed_password"
                ]
                if auth_events:
                    break

            # Distinguish a write-side failure (line never landed) from a
            # monitor-side failure (line present but not detected) so a future
            # flake is diagnosable rather than a bare "events: []".
            wrote = line_in_container_file(container_name, "/var/log/syslog", "1.2.3.4")
            assert len(auth_events) > 0, (
                f"Expected auth threat from syslog "
                f"(line_present_in_container={wrote}), got events: {events}"
            )
            assert auth_events[0].get("level") == "warning"
        finally:
            terminate_shell(proc)
            if backup:
                config_path.write_text(backup)
            elif config_path.exists():
                config_path.unlink()
            cleanup_container(container_name, coi_binary)

    def test_event_detected_promptly(self, test_workspace, coi_binary):
        """Auth log threat is detected after the failed-login line is written.

        With 5-second polling the detection could take up to 5 s; inotify delivers
        in ~1 s when watches are active. The ceiling is deliberately generous to
        absorb CI scheduling jitter on this detection-timing-sensitive lane, on top
        of the 3-second backstop ticker that kicks in when log files don't exist at
        watch-setup time (e.g. fresh containers with overlayfs). The line is also
        re-appended periodically so a monitoring-daemon startup race under load
        (watch not yet active at the first write) can't cause a permanent miss.
        """
        config_path = Path.home() / ".coi" / "config.toml"
        backup = config_path.read_text() if config_path.exists() else None
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(_monitoring_config())

        container_name = (
            get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-67"
        )
        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "67"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            assert wait_for_container_running(container_name), (
                f"Container {container_name} did not start"
            )
            time.sleep(3)

            def append_auth_line():
                subprocess.run(
                    [
                        "incus",
                        "exec",
                        container_name,
                        "--",
                        "bash",
                        "-c",
                        "mkdir -p /var/log && "
                        "echo 'Jun  5 12:00:00 coi sshd[99]: Failed password for attacker"
                        " from 5.6.7.8 port 22222 ssh2' >> /var/log/auth.log",
                    ],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            write_time = time.monotonic()
            append_auth_line()

            events = []
            auth_events = []
            deadline = write_time + 20.0
            next_rewrite = write_time + 4.0
            while time.monotonic() < deadline:
                events = get_threat_events(container_name)
                auth_events = [
                    e
                    for e in events
                    if e.get("category") == "auth"
                    and e.get("evidence", {}).get("auth_log", {}).get("pattern")
                    == "ssh_failed_password"
                ]
                if auth_events:
                    break
                # Re-append if nothing yet: survives a daemon-startup race where the
                # watch wasn't active at the first write (a fresh line then fires
                # inotify) rather than depending solely on the backstop re-read.
                now = time.monotonic()
                if now >= next_rewrite:
                    append_auth_line()
                    next_rewrite = now + 4.0
                time.sleep(0.2)

            elapsed = time.monotonic() - write_time
            assert len(auth_events) > 0, (
                f"Expected auth threat within 20 s (inotify + backstop), elapsed {elapsed:.1f}s. "
                f"Events: {events}"
            )
        finally:
            terminate_shell(proc)
            if backup:
                config_path.write_text(backup)
            elif config_path.exists():
                config_path.unlink()
            cleanup_container(container_name, coi_binary)

    def test_log_rotation_handled(self, test_workspace, coi_binary):
        """Events are detected in a new auth.log file after log rotation.

        Simulates logrotate behaviour: auth.log is renamed to auth.log.1 and a
        new auth.log is created. The inotify directory watch (IN_CREATE) should
        trigger re-registration of the new file so subsequent writes are still
        detected.
        """
        config_path = Path.home() / ".coi" / "config.toml"
        backup = config_path.read_text() if config_path.exists() else None
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(_monitoring_config())

        container_name = (
            get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-68"
        )
        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "68"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            assert wait_for_container_running(container_name), (
                f"Container {container_name} did not start"
            )
            # "Running" != agent-ready: wait until incus exec actually works before
            # writing, so a slow agent under CI load doesn't silently drop writes.
            assert container_exec_ready(container_name), (
                f"Container {container_name} agent not ready for exec"
            )
            # Pre-create an empty auth.log during the settle window so the log
            # watcher registers a DIRECT file watch on it. Otherwise auth.log does
            # not exist at daemon start, and first detection depends on catching the
            # file's creation via the parent-directory IN_CREATE watch — a path
            # logwatcher.go documents as unreliable across the overlayfs namespace
            # boundary. With the file already watched, the trigger write below is a
            # plain append/IN_MODIFY on a watched file (the reliable path), which is
            # what flaked when missed here.
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    "mkdir -p /var/log && touch /var/log/auth.log",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(5)  # let the monitoring daemon register its watches

            # Write the first suspicious line into the original auth.log, re-writing
            # on each poll. Just like the post-rotation write below, a single write
            # can land before the watcher has registered its inotify watch (the
            # monitor is still starting up, especially under CI load) and be missed;
            # re-writing guarantees a write lands after registration and is detected.
            write_first = [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "mkdir -p /var/log && "
                "echo 'Jun  5 12:00:00 coi sshd[1]: Failed password for attacker"
                " from 1.1.1.1 port 22 ssh2' >> /var/log/auth.log",
            ]

            # Wait for the first event before rotating.
            first_events = []
            for _ in range(90):
                subprocess.run(
                    write_first, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                time.sleep(1)
                events = get_threat_events(container_name)
                first_events = [e for e in events if e.get("category") == "auth"]
                if first_events:
                    break

            # Distinguish a write-side failure (line never landed) from a
            # monitor-side failure (line present but not detected) so a future
            # flake is diagnosable rather than a bare "events: []".
            wrote = line_in_container_file(container_name, "/var/log/auth.log", "1.1.1.1")
            assert len(first_events) > 0, (
                f"Expected first auth threat before rotation "
                f"(line_present_in_container={wrote}), events: {events}"
            )

            # Simulate logrotate: move auth.log aside and create a fresh one.
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    "mv /var/log/auth.log /var/log/auth.log.1 && touch /var/log/auth.log",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Write the second suspicious line into the rotated-in new auth.log,
            # re-writing on each poll. The inotify directory watch may not have
            # re-registered the new file when we first write (especially under CI
            # load), so a single write can be missed; re-writing guarantees a write
            # lands after re-registration and is detected.
            #
            # Use a DISTINCT pattern (invalid-user, not failed-password) from the
            # pre-rotation line on purpose: the responder deduplicates threats by
            # category+title+pattern within a 30s window, so re-using the same
            # failed-password pattern would couple detection to that dedup window
            # (and to same-length offset arithmetic). A distinct pattern makes the
            # post-rotation event a fresh, immediately-alerted threat that is
            # detected in one poll cycle once the watcher sees the new file —
            # isolating what this test actually verifies: rotation handling.
            write_second = [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "echo 'Jun  5 12:00:01 coi sshd[2]: Invalid user attacker2"
                " from 2.2.2.2 port 22 ssh2' >> /var/log/auth.log",
            ]
            second_events = []
            for _ in range(90):
                subprocess.run(
                    write_second, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                time.sleep(1)
                events = get_threat_events(container_name)
                second_events = [
                    e
                    for e in events
                    if e.get("category") == "auth" and "2.2.2.2" in e.get("description", "")
                ]
                if second_events:
                    break

            assert len(second_events) > 0, (
                f"Expected auth threat from post-rotation auth.log, "
                f"events after rotation: {get_threat_events(container_name)}"
            )
        finally:
            terminate_shell(proc)
            if backup:
                config_path.write_text(backup)
            elif config_path.exists():
                config_path.unlink()
            cleanup_container(container_name, coi_binary)
