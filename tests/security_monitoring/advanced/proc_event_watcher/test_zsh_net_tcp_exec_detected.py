"""End-to-end tests for host-side PROC_EVENTS monitoring via NETLINK_CONNECTOR."""

from support.monitoring import (
    run_exec_pattern_test,
)


def test_zsh_net_tcp_exec_detected(test_workspace, coi_binary):
    """zsh-net-tcp pattern fires when argv[0] is 'zsh' and 'ztcp' is in cmdline."""
    run_exec_pattern_test(
        test_workspace,
        coi_binary,
        74,
        "zsh-net-tcp",
        "zsh -c ztcp 10.255.255.1 9999",
    )
