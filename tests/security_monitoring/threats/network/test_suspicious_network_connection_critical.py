"""Test network-based threat detection."""

from support.monitoring import (
    cleanup_container,
    get_threat_events,
    hold_connect,
    is_c2_port_threat,
    start_shell,
    wait_for_threats,
)


def test_suspicious_network_connection_critical(test_workspace, enable_monitoring, coi_binary):
    """Test connection to known C2 port triggers CRITICAL threat."""
    container_name, proc = start_shell(test_workspace, coi_binary, 8)
    holder = None
    try:
        # A connected UDP socket stays in /proc/net/udp for every poll; a TCP
        # connect to an external host can be gone before one.
        holder = hold_connect(container_name, "8.8.8.8", 4444, proto="udp")
        threats = wait_for_threats(container_name, is_c2_port_threat("8.8.8.8"))
        assert threats, (
            "no threat for a connection to C2 port 8.8.8.8:4444; "
            f"threat events: {get_threat_events(container_name)}"
        )
        assert any(t.get("level") == "critical" for t in threats), (
            f"Expected a CRITICAL threat for C2 port 4444, got {threats}"
        )
    finally:
        if holder is not None:
            holder.terminate()
        proc.terminate()
        cleanup_container(container_name, coi_binary)
