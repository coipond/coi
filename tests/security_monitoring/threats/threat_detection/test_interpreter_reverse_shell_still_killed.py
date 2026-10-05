"""Test threat detection for different attack types."""

import time

import pytest

from support.monitoring import (
    MALICIOUS_ONELINERS,
    cleanup_container,
    container_absent,
    get_container_state,
    get_threat_events,
    inject_faked_process,
    start_shell,
)


@pytest.mark.parametrize(
    "slot,wrapped", MALICIOUS_ONELINERS, ids=[f"slot{s}" for s, _ in MALICIOUS_ONELINERS]
)
def test_interpreter_reverse_shell_still_killed(
    test_workspace, enable_monitoring, coi_binary, slot, wrapped
):
    """A genuine interpreter reverse shell (socket/IP/host:port present) MUST
    still be detected as CRITICAL and auto-kill the container after the #842
    fix — the tightened heuristic must not create a blind spot."""
    container_name, proc = start_shell(test_workspace, coi_binary, slot)
    try:
        inject_faked_process(container_name, wrapped)

        killed = False
        for _ in range(20):
            time.sleep(1)
            if container_absent(container_name):
                killed = True
                break

        assert killed, (
            f"Real reverse shell {wrapped!r} should be auto-killed, but container "
            f"is {get_container_state(container_name)!r} (blind spot from #842 fix?)"
        )

        events = get_threat_events(container_name)
        reverse_shell_critical = [
            e
            for e in events
            if e.get("level") == "critical" and "reverse shell" in e.get("description", "").lower()
        ]
        assert reverse_shell_critical, (
            f"Expected a reverse-shell CRITICAL event for {wrapped!r}. Events: {events}"
        )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
