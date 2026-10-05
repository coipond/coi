"""End-to-end tests for host-side PROC_EVENTS monitoring via NETLINK_CONNECTOR."""

from support.monitoring import (
    run_exec_pattern_test,
)


def test_perl_socket_connect_exec_detected(test_workspace, coi_binary):
    """perl-socket-connect pattern fires when argv[0] is 'perl' and 'sockaddr_in' is in cmdline."""
    run_exec_pattern_test(
        test_workspace,
        coi_binary,
        71,
        "perl-socket-connect",
        "perl -e use Socket;sockaddr_in(9999,inet_aton(host))",
    )
