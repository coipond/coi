"""Everyday agent commands that look like reverse-shell patterns must not be
flagged. All run in ONE monitored container with auto-kill and auto-pause
on: any false CRITICAL kills it, any false HIGH pauses it, and the audit log
names the culprit. (Class name keeps the monitoring-response CI lane's
`-k TestFalsePositives` selection.)"""

import subprocess
import time

import pytest

from support.monitoring import (
    AGENT_COMMANDS_NOT_REVERSE_SHELLS,
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    inject_literal_process,
    wait_for_container_running,
)


def test_agent_commands_not_flagged(test_workspace, enable_monitoring, coi_binary):
    slot = 92
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", test_workspace, "--slot", str(slot), "--debug"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    container_name = (
        get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + f"-{slot}"
    )
    try:
        if not wait_for_container_running(container_name, timeout=60):
            pytest.fail(f"Container {container_name} did not start")
        time.sleep(10)  # let the monitoring baseline settle

        for cmdline in AGENT_COMMANDS_NOT_REVERSE_SHELLS:
            inject_literal_process(container_name, cmdline)

        # Several poll cycles for the snapshot detector, plus the exec-time
        # watcher, to (not) react.
        time.sleep(12)

        events = get_threat_events(container_name)
        # Only events about the injected commands count: an unrelated
        # HIGH event during the window (e.g. some process gaining root)
        # is not a detector false positive. Match on the first line of
        # each command, which the event description quotes.
        needles = [c.split("\n", 1)[0] for c in AGENT_COMMANDS_NOT_REVERSE_SHELLS]
        flagged = [
            e
            for e in events
            if e.get("level") in ("critical", "high")
            and any(n in e.get("description", "") for n in needles)
        ]
        assert not flagged, "Ordinary agent commands were flagged:\n" + "\n".join(
            f"  {e.get('level')}: {e.get('description')}" for e in flagged
        )
        all_events = "\n".join(
            f"  {e.get('level')} {e.get('category')}: {e.get('description')}" for e in events
        )
        assert not container_absent(container_name), (
            f"Container was killed while running ordinary agent commands. Events:\n{all_events}"
        )
        state = get_container_state(container_name)
        assert state == "Running", (
            f"Container should stay Running, got {state}. Events:\n{all_events}"
        )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
