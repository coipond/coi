"""End-to-end tests for host-side PROC_EVENTS monitoring via NETLINK_CONNECTOR."""

from support.monitoring import (
    run_exec_pattern_test,
)


def test_lua_socket_exec_detected(test_workspace, coi_binary):
    """lua-socket pattern fires when argv[0] is 'lua' and both require('socket') and :connect( appear."""
    run_exec_pattern_test(
        test_workspace,
        coi_binary,
        72,
        "lua-socket",
        'lua -e local s=require("socket").tcp();s:connect("10.255.255.1",9999)',
    )
