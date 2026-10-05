"""Test threat detection for different attack types."""

import time

import pytest

from support.monitoring import (
    BENIGN_ONELINERS,
    cleanup_container,
    container_absent,
    get_container_state,
    get_threat_events,
    inject_faked_process,
    start_shell,
)

# ------------------------------------------------------------------ #
# Issue #842: interpreter one-liners must not be kill-on-sight        #
# ------------------------------------------------------------------ #
#
# Agent Bash tools wrap every command in a shell-snapshot `source` line and
# quote code that almost always contains ':' (PATH entries like /usr/bin:/bin,
# dict/JSON literals like {"ok": True}, URLs, timestamps, log text). The
# reverse-shell detector used to treat a bare ':' as a network indicator, so
# EVERY interpreter one-liner pattern (`python -c`, `python3 -c`, `perl -e`,
# `ruby -e`, `php -r`) became kill-on-sight for agent-driven commands. The fix
# requires a REAL network indicator (socket/tcp/udp/connect keyword, an IP, or
# a host:port endpoint) before these patterns escalate to CRITICAL.
#
# Each argv[0] below is faked via `exec -a` (same mechanism as
# test_reverse_shell_detection) to reproduce the exact wrapped command line the
# monitor reads from /proc/<pid>/cmdline, without needing the real interpreter.
# The (slot, command-line) inputs (BENIGN_ONELINERS / MALICIOUS_ONELINERS) live
# in support/monitoring.py, shared with test_interpreter_reverse_shell_still_killed.


@pytest.mark.parametrize(
    "slot,wrapped", BENIGN_ONELINERS, ids=[f"slot{s}" for s, _ in BENIGN_ONELINERS]
)
def test_benign_interpreter_oneliner_not_killed(
    test_workspace, enable_monitoring, coi_binary, slot, wrapped
):
    """A benign interpreter one-liner (colons but no network endpoint) must NOT
    be treated as a reverse shell and must NOT kill the container (#842)."""
    container_name, proc = start_shell(test_workspace, coi_binary, slot)
    try:
        inject_faked_process(container_name, wrapped)

        # Give the monitor several poll cycles to (not) react.
        time.sleep(8)

        assert not container_absent(container_name), (
            f"Benign one-liner {wrapped!r} was treated as a reverse shell and the "
            "container was killed (regression of issue #842)"
        )
        state = get_container_state(container_name)
        assert state == "Running", (
            f"Container should stay Running for benign {wrapped!r}, got {state}"
        )

        events = get_threat_events(container_name)
        reverse_shell_critical = [
            e
            for e in events
            if e.get("level") == "critical" and "reverse shell" in e.get("description", "").lower()
        ]
        assert not reverse_shell_critical, (
            f"Unexpected reverse-shell CRITICAL event for benign command: {reverse_shell_critical}"
        )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
