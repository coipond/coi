"""A connection from a nested Docker container is flagged like one from the
container's own namespace.

The holders run a UDP socket to a common C2 port (1234, HIGH): one from a
Docker container inside the session (its own network namespace and its own
cgroup under the container's), one from the container's own namespace as a
control. Both must be flagged within the poll window.

The registry is not needed: the Docker container runs an image imported
offline from symlinks, with the container's /usr mounted read-only. Connected
UDP sends nothing."""

from support.helpers import import_nested_docker_image
from support.monitoring import (
    get_threat_events,
    hold_script,
    monitored_shell,
    poll_network_threats,
)

SLOT = 78

CONFIG = """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""

HOLD = """
import sys
import time
from socket import AF_INET, SOCK_DGRAM, socket

s = socket(AF_INET, SOCK_DGRAM)
s.connect((sys.argv[1], 1234))
time.sleep(120)
"""

DOCKER = ("docker", "run", "-i", "--rm", "-v", "/usr:/usr:ro", "coi-usr")

NESTED_HOST = "203.0.113.9"
MAIN_HOST = "203.0.113.10"


def test_nested_docker_connection_flagged(test_workspace, coi_binary):
    with monitored_shell(test_workspace, coi_binary, SLOT, CONFIG) as (container_name, holders):
        rc, out = import_nested_docker_image(coi_binary, container_name)
        assert rc == 0, f"nested Docker image must import: {out}"

        holders.append(hold_script(container_name, HOLD, MAIN_HOST))
        holders.append(hold_script(container_name, HOLD, NESTED_HOST, prefix=DOCKER))

        control = poll_network_threats(container_name, match=f"{MAIN_HOST}:1234")
        assert control, (
            "a C2-port socket in the container's own namespace must be flagged; "
            f"threat events: {get_threat_events(container_name)}"
        )
        nested = poll_network_threats(container_name, match=f"{NESTED_HOST}:1234", max_wait=60)
        assert holders[1].poll() is None, "the Docker container's socket must hold"
        assert nested, (
            "a C2-port socket in a nested Docker container must be flagged; "
            f"threat events: {get_threat_events(container_name)}"
        )
        assert all(t.get("level") == "high" for t in nested), nested
