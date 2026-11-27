"""
End-to-end test for coi run - the /tmp cleanup timers remove files on their
own, with no manual `systemctl start`.

Tests that:
1. The built image enables coi-tmp-cleanup.timer (every 15 minutes) and the
   stock daily systemd-tmpfiles-clean.timer, without the old 15 minute
   override
2. coi-tmp-cleanup.timer fires coi-tmp-cleanup.service, which reads
   tmp_max_size from its EnvironmentFile and removes the oldest files
3. systemd-tmpfiles-clean.timer fires with coi's tmp_max_age rule and removes
   old files

The intervals are 15 minutes and a day, so tests 2 and 3 shorten the timer
with a drop-in (first run 1 second after the timer restarts, then every 5
seconds) and wait for the files to go.
"""

import subprocess
from pathlib import Path

D = "/tmp/coi-cleanup-test"

# Nine 8 MiB files whose access times are 100..92 minutes ago (old1 the
# oldest), and one fresh 8 MiB file: 80 MiB in all. ZFS reports the blocks
# of new files (which coi-tmp-cleanup and du count) a few seconds late, so it
# waits until du sees all 80 MiB.
FILL_TMP = (
    f"d={D}; mkdir -p $d; "
    "for i in 1 2 3 4 5 6 7 8 9; do "
    "dd if=/dev/urandom of=$d/old$i bs=1M count=8 status=none; "
    'touch -a -m -d "-$((101-i)) minutes" $d/old$i; done; '
    "dd if=/dev/urandom of=$d/fresh bs=1M count=8 status=none; "
    't=0; until [ "$(du -sxk /tmp | cut -f1)" -ge 81920 ]; do '
    't=$((t+1)); [ "$t" -lt 120 ] || { echo du-never-saw-80MiB; break; }; sleep 0.5; done; '
)

LIST_TMP = f"echo LEFT: $(ls {D} 2>/dev/null | sort -V | tr '\\n' ' '); "


def _speed_up(timer):
    """Shell that makes timer fire 1s after a restart, then every 5s."""
    dropin = f"/etc/systemd/system/{timer}.d"
    return (
        f"sudo mkdir -p {dropin}; "
        # An empty OnUnitActiveSec= clears every timer of the unit, so it goes first.
        "printf '[Timer]\\nOnUnitActiveSec=\\nOnActiveSec=1s\\nOnUnitActiveSec=5s\\nAccuracySec=1s\\n' "
        f"| sudo tee {dropin}/coi-test-fast.conf >/dev/null; "
        f"sudo systemctl daemon-reload; sudo systemctl restart {timer}; "
    )


def _wait_gone(path, seconds):
    """Shell that waits up to seconds for path to disappear."""
    return (
        f"t=0; while [ -e {path} ]; do t=$((t+1)); "
        f'[ "$t" -lt {seconds * 2} ] || {{ echo still-there-{Path(path).name}; break; }}; '
        "sleep 0.5; done; "
    )


def _write_limits(workspace_dir, lines):
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(parents=True, exist_ok=True)
    (coi_dir / "config.toml").write_text("[limits.disk]\n" + "".join(f"{line}\n" for line in lines))


def _run(coi_binary, workspace_dir, script):
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, (
        f"coi run failed (exit {result.returncode}).\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result.stdout


def _left(stdout):
    """The files LIST_TMP reported as still in the test directory."""
    lines = [line for line in stdout.splitlines() if line.startswith("LEFT:")]
    assert lines, f"no LEFT: line in output:\n{stdout}"
    return lines[-1].split()[1:]


def test_run_tmp_cleanup_timers_scheduled(coi_binary, cleanup_containers, workspace_dir):
    """Both timers are active with their real schedules."""
    out = _run(
        coi_binary,
        workspace_dir,
        'echo "coi-tmp-cleanup.timer $(systemctl is-enabled coi-tmp-cleanup.timer) $(systemctl is-active coi-tmp-cleanup.timer)"; '
        'echo "systemd-tmpfiles-clean.timer $(systemctl is-active systemd-tmpfiles-clean.timer)"; '
        "systemctl cat coi-tmp-cleanup.timer | grep '^OnUnitActiveSec='; "
        "systemctl cat systemd-tmpfiles-clean.timer | grep '^OnUnitActiveSec='; "
        "ls /etc/systemd/system/systemd-tmpfiles-clean.timer.d 2>/dev/null || echo no-tmpfiles-dropin",
    )

    assert "coi-tmp-cleanup.timer enabled active" in out, f"size timer not running:\n{out}"
    # static upstream: started by timers.target, never "enabled"
    assert "systemd-tmpfiles-clean.timer active" in out, f"age timer not running:\n{out}"
    assert "OnUnitActiveSec=15min" in out, f"size check should run every 15 minutes:\n{out}"
    assert "OnUnitActiveSec=1d" in out, f"age check should keep the stock daily schedule:\n{out}"
    assert "no-tmpfiles-dropin" in out, (
        f"the old 15 minute override of systemd-tmpfiles-clean.timer should be gone:\n{out}"
    )


def test_run_tmp_cleanup_size_timer_removes_files(coi_binary, cleanup_containers, workspace_dir):
    """
    coi-tmp-cleanup.timer removes the oldest files once /tmp passes tmp_max_size.

    Flow:
    1. tmp_max_size = 64MiB (cleans down to 32MiB), age limit off
    2. Fill /tmp with 80 MiB: nine old files and one fresh one
    3. Speed up coi-tmp-cleanup.timer and wait for old1 to go
    4. Verify the timer's run logged the removal, the oldest files went
       first, and the newest old file and the fresh one stay
    """
    _write_limits(workspace_dir, ['tmp_max_size = "64MiB"', 'tmp_max_age = "0"'])

    out = _run(
        coi_binary,
        workspace_dir,
        FILL_TMP
        + _speed_up("coi-tmp-cleanup.timer")
        + _wait_gone(f"{D}/old1", 60)
        + LIST_TMP
        + "journalctl -u coi-tmp-cleanup.service --no-pager -o cat | grep 'held' | tail -1",
    )

    assert "still-there-old1" not in out, f"the timer never removed the oldest file:\n{out}"
    assert "held" in out and "removed" in out, (
        f"coi-tmp-cleanup.service did not log a removal:\n{out}"
    )
    left = _left(out)
    removed = [f"old{i}" for i in range(1, 10) if f"old{i}" not in left]
    assert len(removed) >= 6, (
        f"80 MiB down to under 32 MiB needs at least 6 files, left: {left}\n{out}"
    )
    assert removed == [f"old{i}" for i in range(1, len(removed) + 1)], (
        f"files must be removed oldest first, removed: {removed}\n{out}"
    )
    assert "old9" in left and "fresh" in left, f"newer files should stay, left: {left}\n{out}"


def test_run_tmp_cleanup_age_timer_removes_files(coi_binary, cleanup_containers, workspace_dir):
    """
    systemd-tmpfiles-clean.timer removes files older than tmp_max_age.

    systemd-tmpfiles also looks at ctime, which touch cannot set back, so the
    test uses a 20 second age and real waiting: "old" is 25 seconds old when
    the timer fires, "new" a second or two.
    """
    _write_limits(workspace_dir, ['tmp_max_size = "0"', 'tmp_max_age = "20s"'])

    out = _run(
        coi_binary,
        workspace_dir,
        f"d={D}; mkdir -p $d; echo old > $d/old; sleep 25; echo new > $d/new; "
        + _speed_up("systemd-tmpfiles-clean.timer")
        + _wait_gone(f"{D}/old", 15)
        + LIST_TMP,
    )

    assert "still-there-old" not in out, f"the timer never removed the old file:\n{out}"
    left = _left(out)
    assert "new" in left, f"a file younger than tmp_max_age should stay, left: {left}\n{out}"
