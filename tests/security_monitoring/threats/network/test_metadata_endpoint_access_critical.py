"""Test network-based threat detection."""

from support.monitoring import (
    cleanup_container,
    get_threat_events,
    hold_connect,
    is_metadata_threat,
    start_shell,
    wait_for_threats,
)


def test_metadata_endpoint_access_critical(
    test_workspace, enable_monitoring_metadata_open, coi_binary
):
    """Test connection to cloud metadata endpoint triggers CRITICAL threat."""
    container_name, proc = start_shell(test_workspace, coi_binary, 9)
    holder = None
    try:
        # A connected UDP socket stays in /proc/net/udp for every poll; a TCP
        # connect to the endpoint (no server on most hosts) can be gone before one.
        holder = hold_connect(container_name, "169.254.169.254", 80, proto="udp")
        threats = wait_for_threats(container_name, is_metadata_threat)
        assert threats, (
            "no threat for a connection to the metadata endpoint 169.254.169.254:80; "
            f"threat events: {get_threat_events(container_name)}"
        )
        critical = [e for e in threats if e.get("level") == "critical"]
        assert len(critical) > 0, f"Metadata endpoint access should be CRITICAL, got {threats}"
    finally:
        if holder is not None:
            holder.terminate()
        proc.terminate()
        cleanup_container(container_name, coi_binary)
