"""Allowlist mode: traffic to a nested Docker container must not be flagged.

A socket from the container to a Docker container on its own docker0 bridge
(directly, and through docker-proxy for a published port) is RFC1918 but never
leaves the container. A non-local RFC1918 host must still be flagged.

The allowlist blocks registry pulls, so the nested container runs an image
imported offline from symlinks, with the container's /usr mounted read-only."""

import subprocess
import time
from pathlib import Path

from support.helpers import exec_in
from support.monitoring import (
    cleanup_container,
    get_container_state,
    get_threat_events,
    start_shell,
)

SLOT = 73

START_NESTED = """
set -e
timeout 90 sh -c 'until docker info >/dev/null 2>&1; do sleep 1; done'
mkdir -p ~/rootfs && cd ~/rootfs
ln -sfn usr/bin bin && ln -sfn usr/lib lib && ln -sfn usr/lib64 lib64
tar -c bin lib lib64 | docker import - coi-usr >/dev/null
docker run -d --name srv -p 15432:5432 -v /usr:/usr:ro coi-usr python3 -m http.server 5432 >/dev/null
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' srv
"""

# No "socket.socket" in these scripts: the process monitor flags python3 with
# it as a reverse shell and pauses the container.
HOLD_NESTED = """
import sys, time
from socket import create_connection

def connect(addr):
    for _ in range(30):
        try:
            return create_connection(addr)
        except OSError:
            time.sleep(1)
    raise SystemExit(f"cannot connect to {addr}")

held = [connect((sys.argv[1], 5432)), connect(("127.0.0.1", 15432))]
time.sleep(60)
"""

HOLD_LAN = """
import time
from socket import AF_INET, SOCK_DGRAM, socket
s = socket(AF_INET, SOCK_DGRAM)
s.connect(("192.168.255.1", 5432))
time.sleep(60)
"""


def _hold(container_name, script, *args):
    return subprocess.Popen(
        ["incus", "exec", container_name, "--", "python3", "-c", script, *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_allowlist_nested_docker_not_flagged(test_workspace, coi_binary):
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1/32"]

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
"""
    )
    container_name, proc = start_shell(test_workspace, coi_binary, SLOT)
    holders = []
    try:
        rc, out = exec_in(coi_binary, container_name, START_NESTED, timeout=180)
        assert rc == 0, f"nested Docker container must start: {out}"
        nested_ip = out.strip().splitlines()[-1]
        assert nested_ip.startswith("172."), f"unexpected nested container IP: {out}"

        holders.append(_hold(container_name, HOLD_NESTED, nested_ip))
        time.sleep(15)
        assert holders[0].poll() is None, "connections to the nested container must hold"
        assert get_container_state(container_name) == "Running", (
            "traffic to a nested Docker container must not pause the container; "
            f"threat events: {get_threat_events(container_name)}"
        )
        flagged = [e for e in get_threat_events(container_name) if e.get("category") == "network"]
        assert not flagged, f"no nested Docker socket may be flagged, got: {flagged}"

        # Positive control: an RFC1918 host off the docker0 bridge is still flagged.
        holders.append(_hold(container_name, HOLD_LAN))
        threats = []
        deadline = time.monotonic() + 45
        while not threats and time.monotonic() < deadline:
            threats = [
                e
                for e in get_threat_events(container_name)
                if "192.168.255.1:5432" in e.get("description", "")
            ]
            time.sleep(2)
        assert threats, "a socket to a non-local RFC1918 host must still be flagged"
    finally:
        for h in holders:
            h.terminate()
        proc.terminate()
        cleanup_container(container_name, coi_binary)
        if backup is not None:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
