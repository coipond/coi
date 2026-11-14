"""Test for coi shell - allowlist mode: a published port ([ports] pool) used
from the host must not be flagged. The proxy device connects to the service
over 127.0.0.1 inside the container.

Tests that:
- repeated host requests to a server on the pool port leave the container
  running and raise no network threat;
- beside it, port 4444 on the same host (the bridge gateway),
  169.254.169.254 and a LAN host that is not permitted are still flagged."""

import subprocess
import time
from pathlib import Path

from support.helpers import (
    NODE_PORT_SERVER,
    PORT_SENTINEL,
    exec_in,
    expected_pool_port,
    fetch_host_port,
)
from support.monitoring import (
    get_container_state,
    get_threat_events,
    hold_connect,
    is_c2_port_threat,
    is_metadata_threat,
    monitored_shell,
    wait_for_threats,
)

SLOT = 3
UNPERMITTED_LAN_HOST = "192.168.254.254"


# Pause and kill off, so that one positive control does not hide the next; a
# threat is audited either way.
CONFIG = """
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1/32"]

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false

[monitoring.nft]
enabled = true
"""


def test_allowlist_published_port_not_flagged(test_workspace, coi_binary):
    workspace_config = Path(test_workspace) / ".coi" / "config.toml"
    workspace_config.parent.mkdir(exist_ok=True)
    workspace_config.write_text("[ports]\npool = 1\n")
    port = expected_pool_port(test_workspace, slot=SLOT)

    with monitored_shell(test_workspace, coi_binary, SLOT, CONFIG) as (container_name, holders):
        holders.append(
            subprocess.Popen(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--env",
                    f"PORT={port}",
                    "--",
                    "sh",
                    "-c",
                    NODE_PORT_SERVER,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        deadline = time.monotonic() + 15
        body = fetch_host_port(port, timeout_total=60)
        assert PORT_SENTINEL in body, f"host fetch through the pool port returned: {body!r}"
        while time.monotonic() < deadline:
            fetch_host_port(port)
            time.sleep(1)
        time.sleep(5)

        events = get_threat_events(container_name)
        assert get_container_state(container_name) == "Running", f"events: {events}"
        flagged = [e for e in events if e.get("category") == "network"]
        assert not flagged, f"no published-port connection may be flagged, got: {flagged}"

        _, route = exec_in(coi_binary, container_name, "ip -4 route show default")
        gateway = route.split()[2]
        controls = {
            "c2_port_same_host": ([(gateway, 4444, "udp")], is_c2_port_threat(gateway)),
            "metadata": ([("169.254.169.254", 80, "udp")], is_metadata_threat),
            "unpermitted_lan_host": (
                [(UNPERMITTED_LAN_HOST, 443, "udp"), (UNPERMITTED_LAN_HOST, 443, "tcp")],
                lambda e: UNPERMITTED_LAN_HOST in e.get("description", ""),
            ),
        }
        for sockets, _ in controls.values():
            for host, dport, proto in sockets:
                holders.append(hold_connect(container_name, host, dport, proto=proto))
        for name, (_, match) in controls.items():
            assert wait_for_threats(container_name, match), (
                f"control {name} was not flagged; threat events: {get_threat_events(container_name)}"
            )
