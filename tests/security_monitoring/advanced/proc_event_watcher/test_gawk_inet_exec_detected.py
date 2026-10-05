"""End-to-end tests for host-side PROC_EVENTS monitoring via NETLINK_CONNECTOR."""

from support.monitoring import (
    run_exec_pattern_test,
)


def test_gawk_inet_exec_detected(test_workspace, coi_binary):
    """gawk-inet pattern fires when argv[0] is 'gawk' and '/inet/tcp/' is in cmdline."""
    run_exec_pattern_test(
        test_workspace,
        coi_binary,
        73,
        "gawk-inet",
        "gawk /inet/tcp/0/10.255.255.1/9999",
    )
