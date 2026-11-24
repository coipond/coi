"""Test network-based threat detection."""

from support.monitoring import (
    cleanup_container,
    get_threat_events,
    hold_script,
    is_c2_port_threat,
    start_shell,
    wait_for_threats,
)

# Two connected UDP sockets in one process, so the monitor sees both in the
# same poll, before a HIGH threat pauses the container. A UDP socket stays in
# /proc/net/udp whatever happens to its packets; a TCP connect to an external
# host can be gone before a poll.
_HOLD_SUSPICIOUS_PORTS = """
import time
from socket import SOCK_DGRAM, socket
socks = []
for port in (1234, 31337):
    s = socket(type=SOCK_DGRAM)
    s.connect(("8.8.8.8", port))
    socks.append(s)
time.sleep(60)
"""


def test_suspicious_port_high_threat(test_workspace, enable_monitoring, coi_binary):
    """Test connection to suspicious ports (1234, 31337) triggers HIGH/CRITICAL threat."""
    container_name, proc = start_shell(test_workspace, coi_binary, 35)
    holder = None
    try:
        holder = hold_script(container_name, _HOLD_SUSPICIOUS_PORTS)
        for port in (1234, 31337):
            threats = wait_for_threats(container_name, is_c2_port_threat("8.8.8.8", port))
            assert threats, (
                f"no threat for a connection to suspicious port 8.8.8.8:{port}; "
                f"threat events: {get_threat_events(container_name)}"
            )
            for threat in threats:
                assert threat.get("level") in ["high", "critical"], (
                    f"Expected HIGH/CRITICAL for suspicious port, got {threat.get('level')}"
                )
    finally:
        if holder is not None:
            holder.terminate()
        proc.terminate()
        cleanup_container(container_name, coi_binary)
