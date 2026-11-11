"""
Test for coi audit - container mode and --follow.

Tests that:
1. `coi audit <container>` and `coi audit` (container resolved from the
   workspace) print the security monitor's host-side audit log
2. A container with no audit log fails with "no audit log found for container
   <name>"
3. `--follow` on a stopped container fails with "container <name> is not
   running; --follow needs a live container"
4. `--follow` on a running container streams the in-container collector's
   events as JSON lines, announced on stderr with "[audit] streaming from <name>"
"""

import json
import queue
import signal
import subprocess
import threading
import time
from pathlib import Path

from support.helpers import (
    calculate_container_name,
    launch_container,
    run_audit,
    write_trusted_coi_config,
)
from support.monitoring import cleanup_container, inject_literal_process

# Monitoring on, automated responses off: the session must stay up while the
# test reads its audit log.
MONITORING_CONFIG = """
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

SENTINEL = "coi-audit-follow-sentinel-5e2b"


def _audit_log(container_name):
    return Path.home() / ".coi" / "audit" / f"{container_name}.jsonl"


def _start_monitored_shell(coi_binary, workspace_dir):
    env = write_trusted_coi_config(MONITORING_CONFIG)
    env["COI_USE_DUMMY"] = "1"
    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"


def _snapshots(stdout, container_name):
    """The monitor snapshots of container_name in a JSONL stream."""
    records = [json.loads(ln) for ln in stdout.splitlines() if ln.strip()]
    return [r for r in records if r.get("container") == container_name and "processes" in r]


def test_audit_container_prints_monitor_log(coi_binary, cleanup_containers, workspace_dir):
    """
    `coi audit <container>` and `coi audit` from the workspace print the audit
    log the security monitor writes for a monitored session.

    Flow:
    1. coi shell --background with monitoring enabled
    2. Wait until the monitor wrote a snapshot to ~/.coi/audit/<container>.jsonl
    3. coi audit <container>: exit 0, the snapshot is on stdout as JSONL
    4. coi audit with no argument from the workspace: the same log
    """
    container_name = calculate_container_name(workspace_dir, 1)
    log = _audit_log(container_name)
    log.unlink(missing_ok=True)
    try:
        # === Phase 1: Monitored session ===
        _start_monitored_shell(coi_binary, workspace_dir)

        # === Phase 2: Monitor writes the log ===
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if log.exists() and _snapshots(log.read_text(), container_name):
                break
            time.sleep(1)
        assert log.exists() and _snapshots(log.read_text(), container_name), (
            f"the monitor wrote no snapshot to {log}"
        )

        # === Phase 3: Explicit container ===
        r = run_audit(coi_binary, container_name)
        assert r.returncode == 0, f"coi audit {container_name} failed:\n{r.stderr}"
        assert _snapshots(r.stdout, container_name), (
            f"coi audit must print the monitor's snapshots.\nstdout:\n{r.stdout[-2000:]}"
        )

        # === Phase 4: Container resolved from the workspace ===
        r = run_audit(coi_binary, "--workspace", workspace_dir, cwd=workspace_dir)
        assert r.returncode == 0, f"coi audit (auto-resolved) failed:\n{r.stderr}"
        assert _snapshots(r.stdout, container_name), (
            f"coi audit must resolve {container_name} from the workspace.\n"
            f"stdout:\n{r.stdout[-2000:]}\nstderr:\n{r.stderr}"
        )
    finally:
        cleanup_container(container_name, coi_binary)
        log.unlink(missing_ok=True)


def test_audit_container_without_log_errors(coi_binary, cleanup_containers, workspace_dir):
    """
    `coi audit <container>` fails with a clear error when the container has no
    audit log (it was not started with monitoring).

    Flow:
    1. coi container launch (no monitoring, so no audit log)
    2. coi audit <container>: non-zero exit, "no audit log found" error
    """
    container_name = calculate_container_name(workspace_dir, 1)
    _audit_log(container_name).unlink(missing_ok=True)

    launch_container(coi_binary, container_name)

    r = run_audit(coi_binary, container_name)
    assert r.returncode != 0, "coi audit must fail when the container has no audit log"
    assert f"no audit log found for container {container_name}" in r.stderr, (
        f"expected the no-log error.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )


def test_audit_follow_stopped_container_errors(coi_binary, cleanup_containers, workspace_dir):
    """
    `coi audit <container> --follow` refuses a stopped container.

    Flow:
    1. coi container launch, then coi container stop
    2. coi audit <container> --follow: non-zero exit, "is not running" error
    """
    container_name = calculate_container_name(workspace_dir, 1)

    launch_container(coi_binary, container_name)
    result = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"container stop failed:\n{result.stderr}"

    r = run_audit(coi_binary, container_name, "--follow")
    assert r.returncode != 0, "coi audit --follow must fail on a stopped container"
    assert (
        f"container {container_name} is not running; --follow needs a live container" in r.stderr
    ), f"expected the not-running error.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"


def test_audit_follow_running_container_streams(coi_binary, cleanup_containers, workspace_dir):
    """
    `coi audit <container> --follow` on a running monitored session streams the
    in-container collector's events as JSONL until Ctrl+C.

    Flow:
    1. coi shell --background with monitoring enabled
    2. coi audit <container> --follow; wait for the collector.started event
    3. Start a process with a sentinel argv inside the container; its exec
       event must arrive on the stream
    4. SIGINT: exit 0; every stdout line is a JSON event of the container, and
       stderr has "[audit] streaming from <container>"
    """
    container_name = calculate_container_name(workspace_dir, 1)
    log = _audit_log(container_name)
    log.unlink(missing_ok=True)
    proc = None
    try:
        # === Phase 1: Monitored session ===
        _start_monitored_shell(coi_binary, workspace_dir)

        # === Phase 2: Follow ===
        proc = subprocess.Popen(
            [coi_binary, "audit", container_name, "--follow"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        lines = queue.Queue()

        def read_stdout():
            for ln in proc.stdout:
                lines.put(ln)

        threading.Thread(target=read_stdout, daemon=True).start()
        seen = []

        def wait_for(match, timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    ln = lines.get(timeout=1)
                except queue.Empty:
                    continue
                seen.append(ln)
                if match(json.loads(ln)):
                    return True
            return False

        assert wait_for(lambda ev: ev.get("msg") == "collector.started", 60), (
            f"no collector.started event within 60s.\nstdout so far:\n{''.join(seen)}"
        )

        # === Phase 3: A new process shows up on the stream ===
        inject_literal_process(container_name, SENTINEL, seconds=60)
        assert wait_for(
            lambda ev: ev.get("type") == "exec" and SENTINEL in ev.get("args", ""), 60
        ), f"no exec event for the sentinel process.\nstdout so far:\n{''.join(seen)}"

        # === Phase 4: Stop and check the stream ===
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            raise AssertionError("coi audit --follow kept running after SIGINT") from None
        stderr = proc.stderr.read()
        assert proc.returncode == 0, (
            f"a SIGINT stop should exit 0, got {proc.returncode}. stderr:\n{stderr}"
        )
        assert f"[audit] streaming from {container_name}" in stderr, (
            f"expected the streaming notice on stderr, got:\n{stderr}"
        )
        for ln in seen:
            ev = json.loads(ln)
            assert ev.get("container") == container_name, f"event of another container: {ln}"
            assert ev.get("sessionId") == container_name, f"event without the session id: {ln}"
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        cleanup_container(container_name, coi_binary)
        log.unlink(missing_ok=True)
