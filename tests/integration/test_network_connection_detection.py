"""
Integration tests verifying host-side /proc/<pid>/net/{tcp,udp} network
connection detection for suspicious outbound connections.

The monitor reads /proc/<container-init-pid>/net/tcp[6] and udp[6] from the
host (namespaced via init PID), so an in-container attacker cannot blind it.

Tests create long-lived ESTABLISHED connections inside the container so the
connection is stable and visible in /proc/net/* across multiple poll cycles.

For C2-port tests (TCP/UDP to port 4444) we use the container's own IP so
there is always a reachable route and the connection reaches ESTABLISHED
state without relying on external network policy.

For the metadata-endpoint test we assign 169.254.169.254/32 to the loopback
interface inside the container and run a server there, then connect to it so
the socket reaches ESTABLISHED state (stable) rather than SYN_SENT (fragile).
"""

import contextlib
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

# ── helpers ──────────────────────────────────────────────────────────────────


def _container_name(workspace: str) -> str:
    """Derive container name from workspace path (matches Go naming logic)."""
    abs_path = os.path.abspath(workspace)
    digest = hashlib.sha256(abs_path.encode()).hexdigest()[:8]
    return f"coi-{digest}-1"


def _container_state(name: str) -> str:
    result = subprocess.run(
        ["incus", "list", name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return "Unknown"
    containers = json.loads(result.stdout)
    return containers[0].get("status", "Unknown") if containers else "Unknown"


def _wait_running(name: str, timeout: int = 60) -> bool:
    for _ in range(timeout):
        if _container_state(name) == "Running":
            return True
        time.sleep(1)
    return False


def _get_container_ip(container_name: str) -> str:
    """Return the container's primary IPv4 address (eth0)."""
    result = subprocess.run(
        ["incus", "exec", container_name, "--", "hostname", "-I"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return ""
    parts = result.stdout.strip().split()
    return parts[0] if parts else ""


def _wait_for_ip(container_name: str, timeout: int = 30) -> str:
    """Wait until the container has a routable IPv4 address and return it.

    A container can reach Running state before DHCP completes, so polling
    once immediately after _wait_running often returns an empty string.
    """
    for _ in range(timeout):
        ip = _get_container_ip(container_name)
        if ip:
            return ip
        time.sleep(1)
    return ""


def _get_threat_events(container_name: str) -> list[dict]:
    audit_file = Path.home() / ".coi" / "audit" / f"{container_name}.jsonl"
    if not audit_file.exists():
        return []
    events = []
    with audit_file.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    event = json.loads(line)
                    if "level" in event:
                        events.append(event)
                except json.JSONDecodeError:
                    pass
    return events


def _poll_network_threats(container_name: str, max_wait: int = 75, extra_check=None) -> list[dict]:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        events = _get_threat_events(container_name)
        net = [e for e in events if e.get("category") == "network"]
        if net and (extra_check is None or extra_check(net)):
            return net
        time.sleep(2)
    return []


def _cleanup(name: str, coi_binary: str) -> None:
    subprocess.run(
        [coi_binary, "container", "delete", name, "--force"],
        timeout=30,
        check=False,
    )


def _container_absent(name: str) -> bool:
    """True once the container no longer exists (was deleted), as opposed to a
    stopped/frozen container that still exists. The responder's killContainer
    stops AND `incus delete`s the container, so absence — not a non-Running
    status — is the proof an auto-kill fired."""
    result = subprocess.run(
        ["incus", "list", name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return False
    try:
        return len(json.loads(result.stdout)) == 0
    except json.JSONDecodeError:
        return False


def _wait_container_absent(name: str, timeout: int = 120) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _container_absent(name):
            return True
        time.sleep(2)
    return False


def _incus_bash(container_name: str, script: str, timeout: int = 5):
    """Run `bash -c script` in the container. Returns the CompletedProcess, or
    None if the `incus exec` timed out — a slow exec under CI load must read as
    "no answer / not ready", never crash the caller with an uncaught
    TimeoutExpired (these predicates run in the test's critical section)."""
    try:
        return subprocess.run(
            ["incus", "exec", container_name, "--", "bash", "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None


def _start_http_server(container_name: str, port: int, bind: str = "0.0.0.0") -> None:
    """Start a background TCP server on `port` (python3 http.server needs no extra
    packages). Fire-and-forget; the caller waits for it to listen."""
    _incus_bash(
        container_name,
        f"nohup python3 -m http.server {port} --bind {bind} </dev/null &>/dev/null &",
        timeout=10,
    )


def _port_listening(container_name: str, port: int) -> bool:
    # `-H` (no header) is required: with a header, `grep -q .` would always match.
    # An exact ss port filter avoids the substring false-positives of `grep :PORT`
    # (which matched ephemeral ports like 44440-44449 and IPv6 hextets).
    r = _incus_bash(container_name, f"ss -Htln 'sport = :{port}' 2>/dev/null | grep -q .")
    return r is not None and r.returncode == 0


def _wait_port_listening(container_name: str, port: int, attempts: int = 15) -> bool:
    # python3 startup can exceed a fixed sleep under CI load, so poll instead.
    for _ in range(attempts):
        if _port_listening(container_name, port):
            return True
        time.sleep(1)
    return False


def _port_established(container_name: str, port: int) -> bool:
    """True once a connection to/from `port` has completed the TCP handshake (an
    ESTABLISHED socket with `port` as its source OR dest). The exact ss state+port
    filter avoids matching an unrelated socket whose ephemeral port merely
    contains the digits (a `grep :PORT` substring would)."""
    r = _incus_bash(
        container_name,
        f"ss -Htn state established '( sport = :{port} or dport = :{port} )' 2>/dev/null | grep -q .",
    )
    return r is not None and r.returncode == 0


def _wait_port_established(container_name: str, port: int, attempts: int = 10) -> bool:
    for _ in range(attempts):
        if _port_established(container_name, port):
            return True
        time.sleep(2)  # match the monitor's poll_interval_sec; no detection loss
    return False


# ── shared monitoring config ──────────────────────────────────────────────────

_MONITORING_CONFIG = """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 2
file_read_threshold_mb = 100000.0
file_read_rate_mb_per_sec = 100000.0
audit_log_retention_days = 30
"""


@pytest.fixture
def _monitoring_enabled():
    """Write monitoring config to ~/.coi/config.toml, restore on teardown."""
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_MONITORING_CONFIG)
    yield
    if backup is not None:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


# Same as _MONITORING_CONFIG but with the CRITICAL auto-kill response enabled, so
# a CRITICAL network threat drives killContainer end to end (the detection tests
# above deliberately leave the response disabled and assert only the audit event).
_MONITORING_CONFIG_AUTOKILL = """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = true
poll_interval_sec = 2
file_read_threshold_mb = 100000.0
file_read_rate_mb_per_sec = 100000.0
audit_log_retention_days = 30
"""


@pytest.fixture
def _monitoring_autokill():
    """Monitoring config with auto_kill_on_critical=true, restored on teardown."""
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_MONITORING_CONFIG_AUTOKILL)
    yield
    if backup is not None:
        config_path.write_text(backup)
    elif config_path.exists():
        config_path.unlink()


# ── tests ─────────────────────────────────────────────────────────────────────


class TestNetworkConnectionDetection:
    """Host-side /proc/<pid>/net detection of suspicious outbound connections."""

    def test_suspicious_tcp_port_detected(self, coi_binary, tmp_path, _monitoring_enabled):
        """TCP ESTABLISHED connection to C2 port 4444 triggers network threat.

        Uses the container's own IP to guarantee a routable destination and
        start an in-container server so the connection stays ESTABLISHED (not
        SYN_SENT which can disappear quickly if the network rejects the SYN).
        """
        workspace = str(tmp_path / "workspace")
        os.makedirs(workspace, exist_ok=True)
        container_name = _container_name(workspace)

        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", workspace, "--slot", "1"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_running(container_name):
            proc.terminate()
            pytest.skip(f"Container {container_name} not ready")

        # Fire-and-forget connect processes, terminated in `finally` so up to
        # three lingering `incus exec ... sleep(120)` sessions don't leak.
        connect_procs: list[subprocess.Popen] = []
        try:
            # Get container's own IP so we can create a routable connection.
            # Use _wait_for_ip because DHCP may not have completed yet even
            # though the container is already in Running state.
            container_ip = _wait_for_ip(container_name)
            if not container_ip:
                pytest.skip(f"Could not get IP for {container_name}")

            # Connect from inside the container to container_ip:4444. The connect
            # SELF-RETRIES in-container: a single fire-and-forget connect can fail
            # transiently (a dropped SYN on the hairpin route to the container's own
            # IP, an http.server still warming up, or slow python3 startup under CI
            # load), and if that one connect() raises, the process dies with no
            # ESTABLISHED socket — which is exactly what flaked here. Instead, retry
            # create_connection() on a ~2s cadence (each attempt bounded by a 5s
            # connect timeout) until it succeeds, then hold the socket open so it
            # stays ESTABLISHED and visible across the monitor's poll cycles.
            tcp_cmd = (
                "import socket, time\n"
                "sock = None\n"
                "deadline = time.time() + 120\n"
                "while sock is None and time.time() < deadline:\n"
                "    try:\n"
                f"        sock = socket.create_connection(({container_ip!r}, 4444), timeout=5)\n"
                "    except OSError:\n"
                "        time.sleep(2)\n"
                "if sock is not None:\n"
                "    time.sleep(300)\n"
            )
            # Phase 1 — establish a real connection. The in-container connect above
            # retries for up to ~120s, so a single launch normally suffices; the
            # outer loop is a backstop for the rare case where the `incus exec`
            # session itself dies before the connect lands. Each pass (re)ensures the
            # server is listening first. A server that won't come up is
            # environmental → skip, matching how a missing server is handled.
            established = False
            for _ in range(3):
                if not _port_listening(container_name, 4444):
                    _start_http_server(container_name, 4444)
                    if not _wait_port_listening(container_name, 4444):
                        pytest.skip("TCP server on port 4444 did not start within 15 s")
                connect_procs.append(
                    subprocess.Popen(
                        ["incus", "exec", container_name, "--", "python3", "-c", tcp_cmd],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                )
                # Poll generously (90s): the in-container connect keeps retrying, so
                # give it room to win under load before falling back to a re-launch.
                if _wait_port_established(container_name, 4444, attempts=45):
                    established = True
                    break

            assert established, (
                "TCP connection to :4444 never reached ESTABLISHED within the retry "
                "budget — the in-container connect() could not reach the local server "
                "(server or routing problem), so detection could not be exercised.\n"
                f"Container IP: {container_ip}\n"
                f"Port 4444 listening: {_port_listening(container_name, 4444)}"
            )

            # Phase 2 — with a confirmed-live connection (held 120s), poll ONCE for
            # detection with the full budget, so retrying the connect never eats
            # into the detection-latency window.
            net_events = _poll_network_threats(container_name, max_wait=75)
            assert len(net_events) > 0, (
                "Connection to :4444 was ESTABLISHED but no network threat was "
                "detected — a real detector miss, not a connect flake.\n"
                f"Container IP: {container_ip}\n"
                f"All events: {_get_threat_events(container_name)}"
            )
            assert "4444" in json.dumps(net_events), (
                f"Expected port 4444 in threat evidence, got:\n{json.dumps(net_events)}"
            )
        finally:
            for p in connect_procs:
                with contextlib.suppress(Exception):
                    p.terminate()
            _cleanup(container_name, coi_binary)

    def test_suspicious_udp_port_detected(self, coi_binary, tmp_path, _monitoring_enabled):
        """UDP socket connected to container's own port 4444 triggers network threat.

        Uses the container's own IP so connect() succeeds immediately (UDP
        connect just sets the peer address) and the socket is stable in
        /proc/net/udp for the duration of the test.
        """
        workspace = str(tmp_path / "workspace")
        os.makedirs(workspace, exist_ok=True)
        container_name = _container_name(workspace)

        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", workspace, "--slot", "1"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_running(container_name):
            proc.terminate()
            pytest.skip(f"Container {container_name} not ready")

        try:
            container_ip = _wait_for_ip(container_name)
            if not container_ip:
                pytest.skip(f"Could not get IP for {container_name}")

            # UDP connect() just sets the peer address; no server needed.
            # The socket appears in /proc/net/udp with remote = container_ip:4444
            # for the lifetime of the python process.
            udp_cmd = (
                'python3 -c "'
                "import socket, time; "
                "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
                f"s.connect(('{container_ip}', 4444)); "
                "s.send(b'x'); "
                'time.sleep(120)"'
            )
            subprocess.Popen(
                ["incus", "exec", container_name, "--", "bash", "-c", udp_cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            net_events = _poll_network_threats(container_name)

            assert len(net_events) > 0, (
                f"Expected network threat for UDP:4444, got none.\n"
                f"Container IP: {container_ip}\n"
                f"All events: {_get_threat_events(container_name)}"
            )
            assert "4444" in json.dumps(net_events), (
                f"Expected port 4444 in threat evidence, got:\n{json.dumps(net_events)}"
            )
        finally:
            _cleanup(container_name, coi_binary)

    def test_metadata_endpoint_detected(self, coi_binary, tmp_path, _monitoring_enabled):
        """TCP ESTABLISHED connection to 169.254.169.254 triggers critical threat.

        Assigns 169.254.169.254/32 to the container's loopback interface and
        starts an HTTP server there so the client socket reaches ESTABLISHED
        state (stable across poll cycles) rather than SYN_SENT (fragile — the
        SYN is dropped at the Incus bridge and the state times out quickly).
        """
        workspace = str(tmp_path / "workspace")
        os.makedirs(workspace, exist_ok=True)
        container_name = _container_name(workspace)

        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", workspace, "--slot", "1"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_running(container_name):
            proc.terminate()
            pytest.skip(f"Container {container_name} not ready")

        try:
            # Assign the metadata endpoint IP to the loopback interface so we
            # can bind a server there and create a stable ESTABLISHED connection.
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "ip",
                    "addr",
                    "add",
                    "169.254.169.254/32",
                    "dev",
                    "lo",
                ],
                capture_output=True,
                timeout=10,
            )

            # Start an HTTP server bound to the metadata endpoint IP.
            # Poll until the server is listening rather than a fixed sleep — a 2 s
            # sleep is too short under CI load (same race the TCP test hit).
            _start_http_server(container_name, 8080, bind="169.254.169.254")
            if not _wait_port_listening(container_name, 8080):
                pytest.skip("metadata server on port 8080 did not start within 15 s")

            # Connect TCP to 169.254.169.254:8080 → ESTABLISHED, stable in
            # /proc/<init_pid>/net/tcp for the full duration of the test.
            meta_cmd = (
                'python3 -c "'
                "import socket, time; "
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
                "s.connect(('169.254.169.254', 8080)); "
                'time.sleep(120)"'
            )
            subprocess.Popen(
                ["incus", "exec", container_name, "--", "bash", "-c", meta_cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            net_events = _poll_network_threats(
                container_name,
                extra_check=lambda evts: any(e.get("level") == "critical" for e in evts),
            )

            assert len(net_events) > 0, (
                f"Expected network threat for metadata endpoint, got none.\n"
                f"All events: {_get_threat_events(container_name)}"
            )
            critical = [e for e in net_events if e.get("level") == "critical"]
            assert len(critical) > 0, (
                f"Expected CRITICAL level for metadata endpoint, got:\n"
                f"{json.dumps(net_events, indent=2)}"
            )
        finally:
            _cleanup(container_name, coi_binary)

    def test_metadata_endpoint_critical_auto_kills(
        self, coi_binary, tmp_path, _monitoring_autokill
    ):
        """A CRITICAL metadata-endpoint connection drives the responder to KILL.

        The detection tests above run with auto_kill_on_critical=false and assert
        only the audit event, so the network category never exercises the response
        path. This drives it end to end: with auto_kill_on_critical=true, a CRITICAL
        network threat must make killContainer stop AND delete the container, so its
        terminal state is *absent* from `incus list` — not merely non-Running.
        """
        workspace = str(tmp_path / "workspace")
        os.makedirs(workspace, exist_ok=True)
        container_name = _container_name(workspace)

        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", workspace, "--slot", "1"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_running(container_name):
            proc.terminate()
            pytest.skip(f"Container {container_name} not ready")

        try:
            # Same stable-ESTABLISHED technique as test_metadata_endpoint_detected:
            # bind a server on 169.254.169.254 and connect to it so the socket is
            # stable in /proc/<init_pid>/net/tcp across poll cycles.
            subprocess.run(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "ip",
                    "addr",
                    "add",
                    "169.254.169.254/32",
                    "dev",
                    "lo",
                ],
                capture_output=True,
                timeout=10,
            )
            _start_http_server(container_name, 8080, bind="169.254.169.254")
            if not _wait_port_listening(container_name, 8080):
                pytest.skip("metadata server on port 8080 did not start within 15 s")

            # Run the probe from a script file, not `python3 -c "...socket.socket..."`:
            # that command line matches the process detector's reverse-shell
            # patterns, which can then kill the container before the network
            # detector logs the metadata connection this test is about.
            probe = tmp_path / "meta_probe.py"
            probe.write_text(
                "import socket, time\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.connect(('169.254.169.254', 8080))\n"
                "time.sleep(120)\n"
            )
            subprocess.run(
                ["incus", "file", "push", str(probe), f"{container_name}/tmp/meta_probe.py"],
                capture_output=True,
                timeout=10,
                check=True,
            )
            subprocess.Popen(
                ["incus", "exec", container_name, "--", "python3", "/tmp/meta_probe.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # killContainer stops AND deletes, so absence — not a non-Running status
            # — is the proof the CRITICAL response fired. (Accepting "Frozen" would
            # let an auto-PAUSE masquerade as a kill.)
            assert _wait_container_absent(container_name), (
                "auto_kill_on_critical=true: a CRITICAL metadata-endpoint connection "
                "should have killed (stopped AND deleted) the container, but it still "
                f"exists as {_container_state(container_name)!r}.\n"
                f"Events: {_get_threat_events(container_name)}"
            )

            # The kill must be attributed to a CRITICAL network threat. The audit
            # log persists on the host after the container is deleted.
            events = _get_threat_events(container_name)
            assert any(e.get("action") == "killed" for e in events), (
                f"Expected an action='killed' audit event. Events: {events}"
            )
            assert any(
                e.get("category") == "network" and e.get("level") == "critical" for e in events
            ), f"Expected a CRITICAL network threat to drive the kill. Events: {events}"
        finally:
            with contextlib.suppress(Exception):
                proc.terminate()
            _cleanup(container_name, coi_binary)
