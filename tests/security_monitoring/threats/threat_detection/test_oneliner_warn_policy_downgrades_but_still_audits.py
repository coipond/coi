"""Test threat detection for different attack types."""

import time

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_state,
    get_threat_events,
    inject_faked_process,
    start_shell,
)


def test_oneliner_warn_policy_downgrades_but_still_audits(
    test_workspace, enable_monitoring_oneliner_warn, coi_binary
):
    """With reverse_shell_one_liners = "warn" (#842), a PURE interpreter
    one-liner (a `python3 -c` carrying only a host:port endpoint, no
    unambiguous socket indicator) is downgraded to WARNING: it is logged and
    audited but does NOT kill the container. A one-liner that ALSO carries an
    unambiguous indicator (socket.socket, fsockopen, ...) stays CRITICAL even
    under warn — that strong-wins classification is covered by the Go
    TestReverseShellOneLinerPolicy; the unambiguous class kill path is covered
    by test_interpreter_reverse_shell_still_killed and
    test_critical_threat_kills_container."""
    container_name, proc = start_shell(test_workspace, coi_binary, 79)
    try:
        # Pure one-liner: matches `python3 -c` and trips the network gate via
        # a host:port endpoint, but contains NO strong indicator, so it is the
        # genuinely-downgradeable one-liner class.
        inject_faked_process(
            container_name,
            "python3 -c __import__('pty').spawn('/bin/bash') # 10.0.0.1:4444",
        )

        # Give the monitor several poll cycles.
        time.sleep(8)

        # WARN must not kill or pause the container.
        assert not container_absent(container_name), (
            "warn policy must NOT kill the container on a one-liner reverse shell"
        )
        state = get_container_state(container_name)
        assert state == "Running", f"warn policy should keep container Running, got {state}"

        # But the threat must still be audited — as WARNING, not CRITICAL.
        events = get_threat_events(container_name)
        rs_events = [e for e in events if "reverse shell" in e.get("description", "").lower()]
        assert rs_events, f"Expected an audited reverse-shell event under warn. Events: {events}"
        assert any(e.get("level") == "warning" for e in rs_events), (
            f"Expected a WARNING-level reverse-shell event under warn policy, got {rs_events}"
        )
        assert not any(e.get("level") == "critical" for e in rs_events), (
            f"warn policy must not emit a CRITICAL reverse-shell event, got {rs_events}"
        )
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
