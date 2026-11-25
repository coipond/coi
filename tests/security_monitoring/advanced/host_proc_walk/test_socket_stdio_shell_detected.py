"""Test for coi shell - a shell whose stdin/stdout is a TCP socket is flagged
by its file descriptors, not its command line.

Tests that:
- a plain `sh` beside an ESTABLISHED TCP connection, with its stdio on pipes,
  raises no reverse-shell threat;
- an `sh` exec'd with fds 0 and 1 on a TCP socket to a listener in the
  container (no `-i` or `/dev/tcp` in any argv) raises a CRITICAL reverse-shell
  threat within the poll window."""

import subprocess

from support.monitoring import (
    assert_established,
    assert_tcp_state,
    get_threat_events,
    hold_connect,
    hold_script,
    monitored_shell,
    wait_for_threats,
)

SLOT = 59
PORT = 47070

# Kill off, so the container stays up for the audit log check; the threat is
# audited either way.
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

_LISTEN = """
import sys, time
from socket import socket
srv = socket()
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(4)
conns = []
deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    conns.append(srv.accept()[0])
"""

# Connect, then exec sh with fds 0 and 1 on the socket: sh's argv is "sh".
_SOCKET_SHELL = """
import os, sys
from socket import create_connection
s = create_connection(("127.0.0.1", int(sys.argv[1])))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.execvp("sh", ["sh"])
"""


def _is_reverse_shell(event):
    return event.get("title") == "Reverse shell detected"


def test_socket_stdio_shell_detected(test_workspace, coi_binary):
    with monitored_shell(test_workspace, coi_binary, SLOT, CONFIG) as (container_name, holders):
        holders.append(hold_script(container_name, _LISTEN, str(PORT)))
        assert_tcp_state(container_name, "127.0.0.1", PORT, "listening")

        holders.append(hold_connect(container_name, "127.0.0.1", PORT, seconds=120))
        holders.append(
            subprocess.Popen(
                ["incus", "exec", container_name, "--", "sh", "-c", "sleep 120; true"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        assert_established(container_name, holders[1], "127.0.0.1", PORT)
        control = wait_for_threats(container_name, _is_reverse_shell, max_wait=10)
        assert not control, f"a shell on pipes was flagged: {control}"

        socket_shell = hold_script(container_name, _SOCKET_SHELL, str(PORT))
        holders.append(socket_shell)
        found = wait_for_threats(
            container_name,
            lambda e: (
                _is_reverse_shell(e) and "shell stdio on tcp socket" in e.get("description", "")
            ),
            max_wait=30,
        )
        assert socket_shell.poll() is None, f"the socket shell exited ({socket_shell.returncode})"
        assert found, (
            "no reverse-shell threat for sh on a TCP socket; threats: "
            f"{get_threat_events(container_name)}"
        )
        assert all(e.get("level") == "critical" for e in found), found
