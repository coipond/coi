"""End-to-end tests for host-side PROC_EVENTS monitoring via NETLINK_CONNECTOR."""

from support.monitoring import (
    run_exec_pattern_test,
)


def test_ruby_socket_exec_detected(test_workspace, coi_binary):
    """ruby-socket pattern fires when argv[0] starts with 'ruby' and '-rsocket' is in cmdline."""
    run_exec_pattern_test(
        test_workspace,
        coi_binary,
        70,
        "ruby-socket",
        "ruby -rsocket -e exit if fork",
    )
