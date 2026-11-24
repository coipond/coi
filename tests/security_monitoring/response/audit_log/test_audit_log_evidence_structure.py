"""Test audit log format and structure validation."""

from support.monitoring import (
    cleanup_container,
    get_threat_events,
    inject_literal_process,
    start_shell,
    wait_for_threats,
)


def _is_env_scan(event):
    return event.get("level") == "warning" and event.get("category") == "environment"


def test_audit_log_evidence_structure(test_workspace, enable_monitoring, coi_binary):
    """Verify evidence data structure in audit log."""
    container_name, proc = start_shell(test_workspace, coi_binary, 22)
    try:
        # A process whose command line is `env` is flagged as environment
        # scanning on each poll while it lives.
        inject_literal_process(container_name, "env", seconds=60)
        warnings = wait_for_threats(container_name, _is_env_scan)
        assert warnings, (
            "no environment-scanning WARNING for an `env` process; "
            f"threat events: {get_threat_events(container_name)}"
        )

        for event in warnings:
            evidence = event.get("evidence")
            assert isinstance(evidence, dict), f"Evidence should be a dict, got {evidence!r}"
            process = evidence.get("process")
            assert isinstance(process, dict), f"Evidence should hold the process, got {evidence}"
            assert process.get("command", "").split()[0] == "env", process
            assert process.get("pid", 0) > 0, process
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
