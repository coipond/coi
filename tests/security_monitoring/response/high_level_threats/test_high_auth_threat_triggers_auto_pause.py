"""Test HIGH-level threats that trigger auto-pause."""

import subprocess
import time
from pathlib import Path

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_high_auth_threat_triggers_auto_pause(test_workspace, coi_binary):
    """A HIGH auth-log threat with auto_pause_on_high=true FREEZES the container.

    This is the CI-runnable coverage of the auto-PAUSE response.
    test_large_file_read_triggers_auto_pause (same directory) is skipped on GitHub
    Actions because cgroup io.stat does not track bind-mount reads there, and
    every other HIGH test disables auto-pause — so pauseContainer otherwise
    never runs in CI at all. A log-file HIGH threat (sudo "not in the sudoers
    file") needs no cgroup accounting, so it drives the pause path end to end
    on GHA: the container must reach the Frozen state AND record an
    action="paused" audit event driven by a HIGH threat. This is an
    unconditional assertion — a broken auto-pause fails the whole run red.
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
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
process_count_threshold = 9999
process_spawn_rate_threshold = 9999
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-62"
    )
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "62", "--debug"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )
        time.sleep(3)

        # Reliable re-inject trigger (mirrors test_sudo_not_in_sudoers_triggers_high):
        # the LogWatcher polls auth.log, so re-appending survives a monitoring
        # daemon startup race. A frozen container can't exec, so re-append only
        # while it is still Running.
        def append_sudoers_line():
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    "mkdir -p /var/log && "
                    "echo 'Jun  5 12:00:01 coi sudo: hacker is not in the sudoers file. "
                    "This incident will be reported.' >> /var/log/auth.log",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        append_sudoers_line()

        # Poll until the container is actually FROZEN. Do NOT break on the
        # action="paused" audit event: responder.go writes that event
        # (logThreat) BEFORE it runs `incus pause` (pauseContainer), so the
        # event becomes visible a beat before the container freezes — breaking
        # on it would let the assertion below observe a still-Running state and
        # fail on a healthy auto-pause. The Frozen state is the definitive
        # signal, and the event is guaranteed already written by then.
        for i in range(60):
            state = get_container_state(container_name)
            if state == "Frozen":
                break
            if i and i % 8 == 0 and state == "Running":
                append_sudoers_line()
            time.sleep(1)

        final_state = get_container_state(container_name)
        events = get_threat_events(container_name)
        paused_events = [e for e in events if e.get("action") == "paused"]
        high_threats = [e for e in events if e.get("level") == "high"]

        assert final_state == "Frozen", (
            "auto_pause_on_high=true: a HIGH auth threat should FREEZE (pause) the "
            f"container, but its state is {final_state!r}. Events: {events}"
        )
        assert paused_events, f"Expected an action='paused' audit event. Events: {events}"
        assert high_threats, f"Expected a HIGH threat to drive the pause. Events: {events}"
    finally:
        # A frozen container must be unfrozen before it can be torn down cleanly.
        subprocess.run(
            [coi_binary, "unfreeze", container_name],
            capture_output=True,
            timeout=30,
            check=False,
        )
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)
