"""Test automated threat response system."""

from support.monitoring import (
    cleanup_container,
    forensic_copies,
    get_container_state,
    trigger_critical_and_wait_kill,
)


def test_kill_without_forensics_by_default(test_workspace, enable_monitoring, coi_binary):
    """Default (forensics_on_kill unset = off): the kill leaves no copy."""
    proc, container_name, killed = trigger_critical_and_wait_kill(
        coi_binary, test_workspace, slot=5
    )
    try:
        assert killed, (
            f"Container should be auto-killed, still {get_container_state(container_name)!r}"
        )
        copies = forensic_copies(container_name)
        assert not copies, f"no forensic copy expected when disabled, got {copies}"
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
