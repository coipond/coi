"""Test for coi shell - benign workloads in the modes where users hit false
positives: allowlist mode with both monitors on, and the hardened profile
(restricted, both monitors, pause and kill). Every threshold is at its default.

Tests that:
- a build script, a small file read, a script that imports socket, an nc
  check, ordinary agent commands and a connection to a permitted LAN service
  leave the container running and raise no HIGH or CRITICAL threat, with pause
  and kill on;
- beside them, in each mode, port 4444 on the same LAN host, 169.254.169.254
  and a LAN host that is not permitted are still flagged."""

import subprocess
import time
from pathlib import Path

import pytest

from support.helpers import fake_lan
from support.monitoring import (
    AGENT_COMMANDS_NOT_REVERSE_SHELLS,
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    hold_connect,
    inject_literal_process,
    is_metadata_threat,
    wait_for_container_running,
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
    the monitoring response itself; the LAN service entry is added to both."""
    head = ""
    if mode == "allowlist":
        flag = "true" if respond else "false"
        head = f"""
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1/32"]

[monitoring]
enabled = true
auto_pause_on_high = {flag}
auto_kill_on_critical = {flag}

[monitoring.nft]
enabled = true
"""
    return (
        head
        + f"""
[[network.hosts]]
ip = "{lan_host}"
hostnames = ["service.lan"]
ports = [443, 4444]
"""
    )


def _start(test_workspace, coi_binary, mode, slot):
    argv = [coi_binary, "shell", "--workspace", test_workspace, "--slot", str(slot), "--debug"]
    if mode == "hardened":
        argv += ["--profile", "hardened"]
    proc = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    container_name = (
        get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + f"-{slot}"
    )
    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")
    time.sleep(10)  # let the monitoring baseline settle
    return container_name, proc


def _with_config(text):
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(text)

    def restore():
        if backup is not None:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()

    return restore


def _exec(container_name, *argv):
    subprocess.run(
        ["incus", "exec", container_name, "--", *argv],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )


@pytest.mark.parametrize("mode,slot", [("allowlist", 93), ("hardened", 94)])
def test_benign_workloads_not_flagged(test_workspace, coi_binary, mode, slot):
    workspace = Path(test_workspace)
    (workspace / "build.sh").write_text(BUILD_SCRIPT)
    (workspace / "build.sh").chmod(0o755)
    (workspace / "package.json").write_text('{"name": "test", "version": "1.0.0"}')
    (workspace / "data.txt").write_text("Some data\n" * 1000)
    (workspace / "benign.py").write_text(IMPORT_SOCKET_SCRIPT)

    with fake_lan(SUBNET, hosts=(20,), ports=(443,)) as (lan_host,):
        restore = _with_config(_config(mode, lan_host, respond=True))
        container_name, proc = _start(test_workspace, coi_binary, mode, slot)
        holders = []
        try:
            holders.append(hold_connect(container_name, "service.lan", 443))
            _exec(container_name, "bash", "/workspace/build.sh")
            _exec(container_name, "cat", "/workspace/data.txt")
            _exec(container_name, "python3", "/workspace/benign.py")
            _exec(container_name, "bash", "-c", "which nc || echo 'nc not found'")
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
        finally:
            for h in holders:
                h.terminate()
            proc.terminate()
            cleanup_container(container_name, coi_binary)
            restore()


def _same_host_c2_port(lan_host):
    return lambda e: lan_host in str(e) and "4444" in str(e)


def _unpermitted_lan_host(other):
    return lambda e: other in e.get("description", "")


CONTROLS = {
    "c2_port_same_host": lambda hosts: ((hosts[0], 4444), _same_host_c2_port(hosts[0])),
    "metadata": lambda hosts: (("169.254.169.254", 80), is_metadata_threat),
    "unpermitted_lan_host": lambda hosts: ((hosts[1], 443), _unpermitted_lan_host(hosts[1])),
}


def test_positive_controls_allowlist(test_workspace, coi_binary):
    """Allowlist mode with pause and kill off, so one container sees every
    control while the benign LAN connection stays open beside them."""
    with fake_lan(SUBNET, hosts=(20, 21), ports=(443, 4444)) as hosts:
        restore = _with_config(_config("allowlist", hosts[0], respond=False))
        container_name, proc = _start(test_workspace, coi_binary, "allowlist", 95)
        holders = []
        try:
            holders.append(hold_connect(container_name, "service.lan", 443))
            checks = {}
            for name, control in CONTROLS.items():
                (host, port), match = control(hosts)
                holders.append(hold_connect(container_name, host, port))
                checks[name] = match
            for name, match in checks.items():
                assert wait_for_threats(container_name, match), (
                    f"allowlist: control {name} was not flagged; "
                    f"threat events: {get_threat_events(container_name)}"
                )
            benign = [e for e in get_threat_events(container_name) if f"{hosts[0]}:443" in str(e)]
            assert not benign, f"allowlist: the permitted LAN service was flagged: {benign}"
        finally:
            for h in holders:
                h.terminate()
            proc.terminate()
            cleanup_container(container_name, coi_binary)
            restore()


@pytest.mark.parametrize(
    "control,slot",
    [("c2_port_same_host", 96), ("metadata", 97), ("unpermitted_lan_host", 98)],
)
def test_positive_controls_hardened(test_workspace, coi_binary, control, slot):
    """The hardened profile always pauses or kills on the first threat, so each
    control gets its own container."""
    with fake_lan(SUBNET, hosts=(20, 21), ports=(443, 4444)) as hosts:
        restore = _with_config(_config("hardened", hosts[0], respond=True))
        container_name, proc = _start(test_workspace, coi_binary, "hardened", slot)
        holder = None
        try:
            (host, port), match = CONTROLS[control](hosts)
            holder = hold_connect(container_name, host, port)
            assert wait_for_threats(container_name, match), (
                f"hardened: control {control} was not flagged; "
                f"threat events: {get_threat_events(container_name)}"
            )
        finally:
            if holder is not None:
                holder.terminate()
            proc.terminate()
            cleanup_container(container_name, coi_binary)
            restore()
