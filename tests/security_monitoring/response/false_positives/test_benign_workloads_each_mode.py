"""Test for coi shell - benign workloads in each network mode, beside positive
controls: open mode, allowlist mode, and the hardened profile (restricted, pause
and kill). Both monitors are on and every threshold is at its default.

Tests that:
- a build script, a small file read, a script that imports socket, an nc
  check, ordinary agent commands (the workloads of the other false_positives
  tests) and an ESTABLISHED connection to a LAN service leave the container
  running and raise no HIGH or CRITICAL threat, with pause and kill on;
- beside them, in each mode, port 4444 on the same LAN host and
  169.254.169.254 are still flagged, and so is a LAN host that is not
  permitted (allowlist and hardened only: open mode allows the LAN)."""

import time
from pathlib import Path

import pytest

from support.helpers import exec_in, fake_lan
from support.monitoring import (
    AGENT_COMMANDS_NOT_REVERSE_SHELLS,
    assert_established,
    container_absent,
    get_container_state,
    get_threat_events,
    hold_connect,
    inject_literal_process,
    is_c2_port_threat,
    is_metadata_threat,
    monitored_shell,
    wait_for_threats,
)

SUBNET = "192.168.205"

BUILD_SCRIPT = """#!/bin/bash
echo "Building..."
ls -la
cat package.json
echo "Build complete"
"""

IMPORT_SOCKET_SCRIPT = """import socket
import time

print("Hello world")
time.sleep(2)
"""


def _config(mode, lan_host, respond):
    """User config for the mode. The hardened profile sets the network mode and
    the monitoring response itself. Allowlist and hardened reach the LAN service
    through a [[network.hosts]] entry; open mode reaches any LAN host."""
    flag = "true" if respond else "false"
    monitoring = f"""
[monitoring]
enabled = true
auto_pause_on_high = {flag}
auto_kill_on_critical = {flag}

[monitoring.nft]
enabled = true
"""
    service = f"""
[[network.hosts]]
ip = "{lan_host}"
hostnames = ["service.lan"]
ports = [443, 4444]
"""
    if mode == "open":
        return '[network]\nmode = "open"\n' + monitoring
    if mode == "allowlist":
        return (
            '[network]\nmode = "allowlist"\nallowed_domains = ["1.1.1.1/32"]\n'
            + monitoring
            + service
        )
    return service


def _shell(test_workspace, coi_binary, mode, slot, lan_host, respond):
    extra = ["--profile", "hardened"] if mode == "hardened" else []
    return monitored_shell(
        test_workspace, coi_binary, slot, _config(mode, lan_host, respond), extra
    )


def _service(mode, lan_host):
    return lan_host if mode == "open" else "service.lan"


@pytest.mark.parametrize("mode,slot", [("open", 92), ("allowlist", 93), ("hardened", 94)])
def test_benign_workloads_not_flagged(test_workspace, coi_binary, mode, slot):
    """Pause and kill on: any false HIGH pauses the container, any false
    CRITICAL kills it, and the audit log names the culprit."""
    workspace = Path(test_workspace)
    (workspace / "build.sh").write_text(BUILD_SCRIPT)
    (workspace / "build.sh").chmod(0o755)
    (workspace / "package.json").write_text('{"name": "test", "version": "1.0.0"}')
    (workspace / "data.txt").write_text("Some data\n" * 1000)
    (workspace / "benign.py").write_text(IMPORT_SOCKET_SCRIPT)

    with (
        fake_lan(SUBNET, hosts=(20,), ports=(443,)) as (lan_host,),
        _shell(test_workspace, coi_binary, mode, slot, lan_host, respond=True) as (
            container_name,
            holders,
        ),
    ):
        holders.append(hold_connect(container_name, _service(mode, lan_host), 443))
        assert_established(container_name, holders[-1], lan_host, 443)
        for cmd in (
            "bash /workspace/build.sh",
            "cat /workspace/data.txt",
            "python3 /workspace/benign.py",
            "which nc || echo 'nc not found'",
        ):
            exec_in(coi_binary, container_name, cmd, timeout=30)
        for cmdline in AGENT_COMMANDS_NOT_REVERSE_SHELLS:
            inject_literal_process(container_name, cmdline)

        # Several poll cycles for both monitors to (not) react.
        time.sleep(15)

        events = get_threat_events(container_name)
        listing = "\n".join(
            f"  {e.get('level')} {e.get('category')}: {e.get('description')}" for e in events
        )
        assert not container_absent(container_name), (
            f"{mode}: benign workloads killed the container. Events:\n{listing}"
        )
        state = get_container_state(container_name)
        assert state == "Running", (
            f"{mode}: container should stay Running, got {state}. Events:\n{listing}"
        )
        flagged = [e for e in events if e.get("level") in ("high", "critical")]
        assert not flagged, f"{mode}: benign workloads were flagged:\n{listing}"


def _unpermitted_lan_host(other):
    return lambda e: other in e.get("description", "")


# name -> (sockets to hold as (host index or address, port, proto), matcher).
CONTROLS = {
    "c2_port_same_host": lambda hosts: ([(hosts[0], 4444, "tcp")], is_c2_port_threat(hosts[0])),
    "metadata": lambda hosts: ([("169.254.169.254", 80, "udp")], is_metadata_threat),
    "unpermitted_lan_host": lambda hosts: (
        [(hosts[1], 443, "udp"), (hosts[1], 443, "tcp")],
        _unpermitted_lan_host(hosts[1]),
    ),
}


@pytest.mark.parametrize("mode,slot", [("open", 95), ("allowlist", 96)])
def test_positive_controls(test_workspace, coi_binary, mode, slot):
    """Pause and kill off, so one container sees every control while the
    benign LAN connection stays open beside them."""
    controls = [c for c in CONTROLS if mode != "open" or c != "unpermitted_lan_host"]
    with (
        fake_lan(SUBNET, hosts=(20, 21), ports=(443, 4444)) as hosts,
        _shell(test_workspace, coi_binary, mode, slot, hosts[0], respond=False) as (
            container_name,
            holders,
        ),
    ):
        holders.append(hold_connect(container_name, _service(mode, hosts[0]), 443))
        assert_established(container_name, holders[-1], hosts[0], 443)
        checks = {}
        for name in controls:
            sockets, match = CONTROLS[name](hosts)
            for host, port, proto in sockets:
                holders.append(hold_connect(container_name, host, port, proto=proto))
            checks[name] = match
        for name, match in checks.items():
            assert wait_for_threats(container_name, match, nft=True), (
                f"{mode}: control {name} was not flagged; "
                f"threat events: {get_threat_events(container_name, nft=True)}"
            )
        benign = [
            e
            for e in get_threat_events(container_name, nft=True)
            if f"{hosts[0]}:443" in e.get("description", "")
        ]
        assert not benign, f"{mode}: the LAN service was flagged: {benign}"


@pytest.mark.parametrize(
    "control,slot",
    [("c2_port_same_host", 97), ("metadata", 98), ("unpermitted_lan_host", 99)],
)
def test_positive_controls_hardened(test_workspace, coi_binary, control, slot):
    """The hardened profile always pauses or kills on the first threat, so each
    control gets its own container. The nft monitor may respond first, so its
    log counts too."""
    with (
        fake_lan(SUBNET, hosts=(20, 21), ports=(443, 4444)) as hosts,
        _shell(test_workspace, coi_binary, "hardened", slot, hosts[0], respond=True) as (
            container_name,
            holders,
        ),
    ):
        sockets, match = CONTROLS[control](hosts)
        for host, port, proto in sockets:
            holders.append(hold_connect(container_name, host, port, proto=proto))
        assert wait_for_threats(container_name, match, nft=True), (
            f"hardened: control {control} was not flagged; "
            f"threat events: {get_threat_events(container_name, nft=True)}"
        )
