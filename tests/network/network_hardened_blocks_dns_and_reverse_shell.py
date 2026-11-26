"""
Test for network isolation - the hardened profile allows only its allowlist.

Tests that, in a `coi run --profile hardened` session:
1. A DNS TXT query to a public resolver (8.8.8.8:53) fails
2. A TCP connect to a non-listed public host (1.1.1.1:443) fails
3. A reverse-shell style connect to a non-listed host:port (1.0.0.1:9001) fails
4. An HTTPS request to a listed host (rubygems.org) works
"""

import subprocess

from support.helpers import write_profile

# Each check prints <NAME>_OPEN or <NAME>_BLOCKED. Run from a file, not
# `python3 -c`: a command line naming socket/tcp is a reverse shell to the
# process monitor.
PROBE = """
import socket
import urllib.request


def check(name, fn):
    try:
        fn()
        print(name + "_OPEN", flush=True)
    except Exception as e:
        print(name + "_BLOCKED " + type(e).__name__, flush=True)


def dns_txt():
    query = bytes.fromhex("abcd01000001000000000000")
    query += b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split("."))
    query += bytes.fromhex("0000100001")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.connect(("8.8.8.8", 53))
    s.send(query)
    if s.recv(512)[:2] != query[:2]:
        raise RuntimeError("unexpected answer")


def connect(host, port):
    socket.create_connection((host, port), timeout=5).close()


check("DNS_TXT", dns_txt)
check("TCP_UNLISTED", lambda: connect("1.1.1.1", 443))
check("REVERSE_SHELL", lambda: connect("1.0.0.1", 9001))
check("LISTED_HOST", lambda: urllib.request.urlopen("https://rubygems.org", timeout=20))
"""

# The hardened network policy with the monitor's auto-pause off: each blocked
# probe is a HIGH "not in allowlist" threat, and a paused container would stop
# the probe before it reports.
PROFILE = """inherits = "hardened"

[monitoring]
auto_pause_on_high = false
"""


def test_hardened_blocks_dns_and_reverse_shell(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that the hardened profile blocks DNS and non-listed egress.

    Flow:
    1. Write the probe and a profile inheriting hardened (auto-pause off)
    2. Run the probe with coi run --profile
    3. Verify DNS and non-listed connects failed, the listed host worked
    """
    with open(f"{workspace_dir}/probe.py", "w") as f:
        f.write(PROBE)
    write_profile(workspace_dir, "hardened-probe", PROFILE)

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--profile",
            "hardened-probe",
            "--",
            "python3",
            "/workspace/probe.py",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )

    combined_output = result.stdout + result.stderr
    assert result.returncode == 0, f"Run should succeed. Output:\n{combined_output}"

    for want in ("DNS_TXT_BLOCKED", "TCP_UNLISTED_BLOCKED", "REVERSE_SHELL_BLOCKED"):
        assert want in combined_output, f"Missing {want}. Output:\n{combined_output}"
    assert "LISTED_HOST_OPEN" in combined_output, (
        f"rubygems.org should be reachable. Output:\n{combined_output}"
    )
