"""
Test for coi run - the /tmp cleanup limits ([limits.disk] tmp_max_size and
tmp_max_age).

Tests that:
1. Unset limits give the defaults (4GiB, 7d) in the container
2. Over tmp_max_size, coi-tmp-cleanup removes the least recently used files
   until /tmp holds under half of it, and keeps recent files
3. tmp_max_age removes files not used for that long, and keeps newer ones
4. "0" turns both limits off: nothing is removed
5. A restarted persistent container gets a changed limit
"""

import subprocess
from pathlib import Path

from support.helpers import write_workspace_container_config

ENV_FILE = "/etc/default/coi-tmp-cleanup"
CONF_FILE = "/etc/tmpfiles.d/coi-tmp-cleanup.conf"

# Nine 8 MiB files whose access times are 100..92 minutes ago (old1 the
# oldest), and one fresh 8 MiB file: 80 MiB in all. ZFS reports the blocks
# of new files (which coi-tmp-cleanup and du count) a few seconds late, so it
# waits until du sees all 80 MiB.
FILL_TMP = (
    "d=/tmp/coi-cleanup-test; mkdir -p $d; "
    "for i in 1 2 3 4 5 6 7 8 9; do "
    "dd if=/dev/urandom of=$d/old$i bs=1M count=8 status=none; "
    'touch -a -m -d "-$((101-i)) minutes" $d/old$i; done; '
    "dd if=/dev/urandom of=$d/fresh bs=1M count=8 status=none; "
    't=0; until [ "$(du -sxk /tmp | cut -f1)" -ge 81920 ]; do '
    't=$((t+1)); [ "$t" -lt 120 ] || { echo du-never-saw-80MiB; break; }; sleep 0.5; done; '
)

LIST_TMP = "echo LEFT: $(ls /tmp/coi-cleanup-test | sort -V | tr '\\n' ' '); "


def _write_limits(workspace_dir, lines):
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(parents=True, exist_ok=True)
    (coi_dir / "config.toml").write_text("[limits.disk]\n" + "".join(f"{line}\n" for line in lines))


def _run(coi_binary, workspace_dir, script, extra_args=()):
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, *extra_args, "--", "sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert result.returncode == 0, (
        f"coi run failed (exit {result.returncode}).\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result.stdout


def _left(stdout):
    """The files LIST_TMP reported as still in /tmp/coi-cleanup-test."""
    lines = [line for line in stdout.splitlines() if line.startswith("LEFT:")]
    assert lines, f"no LEFT: line in output:\n{stdout}"
    return lines[-1].split()[1:]


def test_run_tmp_cleanup_defaults(coi_binary, cleanup_containers, workspace_dir):
    """Without tmp_max_size / tmp_max_age the container gets 4GiB and 7d."""
    out = _run(coi_binary, workspace_dir, f"cat {ENV_FILE} {CONF_FILE}")

    assert "TMP_MAX_BYTES=4294967296" in out, f"default size should be 4GiB. Output:\n{out}"
    assert "D /tmp 1777 root root 7d" in out, f"default age should be 7d. Output:\n{out}"


def test_run_tmp_cleanup_size_removes_least_recently_used(
    coi_binary, cleanup_containers, workspace_dir
):
    """
    Over tmp_max_size the oldest files go first, until /tmp is under half of it.

    Flow:
    1. tmp_max_size = 64MiB (low mark 32MiB), age limit off
    2. Fill /tmp with 80 MiB: nine old files and one fresh one
    3. Run coi-tmp-cleanup.service once (a oneshot: start waits for it)
    4. Verify the oldest files were removed, oldest first, and enough of them
       to get under 32 MiB, while the newest old file and the fresh one stay
    """
    _write_limits(workspace_dir, ['tmp_max_size = "64MiB"', 'tmp_max_age = "0"'])

    out = _run(
        coi_binary,
        workspace_dir,
        f"cat {ENV_FILE}; "
        + FILL_TMP
        + "sudo systemctl start coi-tmp-cleanup.service; "
        + LIST_TMP
        + "sudo journalctl -u coi-tmp-cleanup.service --no-pager -o cat | tail -3",
    )

    assert f"TMP_MAX_BYTES={64 << 20}" in out, f"tmp_max_size not applied. Output:\n{out}"
    left = _left(out)
    removed = [f"old{i}" for i in range(1, 10) if f"old{i}" not in left]
    # 80 MiB down to under 32 MiB: at least six 8 MiB files.
    assert len(removed) >= 6, f"expected at least 6 files removed, left: {left}\n{out}"
    assert removed == [f"old{i}" for i in range(1, len(removed) + 1)], (
        f"files must be removed oldest first, removed: {removed}\n{out}"
    )
    assert "old9" in left, f"the newest old file should stay, left: {left}\n{out}"
    assert "fresh" in left, f"a file used in the last hour must stay, left: {left}\n{out}"


def test_run_tmp_cleanup_age_removes_old_files(coi_binary, cleanup_containers, workspace_dir):
    """
    tmp_max_age removes files not used for that long.

    systemd-tmpfiles also looks at ctime, which touch cannot set back, so the
    test uses a 3 second age and real waiting instead of back-dated files.
    """
    _write_limits(workspace_dir, ['tmp_max_size = "0"', 'tmp_max_age = "3s"'])

    out = _run(
        coi_binary,
        workspace_dir,
        f"cat {CONF_FILE}; "
        "d=/tmp/coi-cleanup-test; mkdir -p $d; echo old > $d/old; sleep 6; "
        "echo new > $d/new; "
        "sudo systemctl start systemd-tmpfiles-clean.service; "
        "echo LEFT: $(ls $d 2>/dev/null | sort | tr '\\n' ' ')",
    )

    assert "D /tmp 1777 root root 3s" in out, f"tmp_max_age not applied. Output:\n{out}"
    left = _left(out)
    assert "old" not in left, (
        f"a file unused for longer than tmp_max_age should be removed, left: {left}\n{out}"
    )
    assert "new" in left, f"a newer file should stay, left: {left}\n{out}"


def test_run_tmp_cleanup_off(coi_binary, cleanup_containers, workspace_dir):
    """Setting both limits to "0" turns them off: a full /tmp is left alone."""
    _write_limits(workspace_dir, ['tmp_max_size = "0"', 'tmp_max_age = "0"'])

    out = _run(
        coi_binary,
        workspace_dir,
        f"cat {ENV_FILE} {CONF_FILE}; "
        + FILL_TMP
        + "sleep 2; sudo systemctl start coi-tmp-cleanup.service systemd-tmpfiles-clean.service; "
        + LIST_TMP,
    )

    assert "TMP_MAX_BYTES=0" in out, f"tmp_max_size = 0 not applied. Output:\n{out}"
    assert "D /tmp 1777 root root -" in out, f"tmp_max_age = 0 not applied. Output:\n{out}"
    left = _left(out)
    assert sorted(left) == sorted([f"old{i}" for i in range(1, 10)] + ["fresh"]), (
        f"no file should be removed with both limits off, left: {left}\n{out}"
    )


def test_run_tmp_cleanup_restart_applies_changed_limits(
    coi_binary, cleanup_containers, workspace_dir
):
    """A restarted persistent container gets the limits now in the config."""
    _write_limits(workspace_dir, ['tmp_max_size = "1GiB"', 'tmp_max_age = "2d"'])
    write_workspace_container_config(workspace_dir, persistent=True)
    args = ("--slot", "8")

    out = _run(coi_binary, workspace_dir, f"cat {ENV_FILE} {CONF_FILE}", args)
    assert f"TMP_MAX_BYTES={1 << 30}" in out and "root root 2d" in out, (
        f"first run should apply 1GiB/2d. Output:\n{out}"
    )

    _write_limits(workspace_dir, ['tmp_max_size = "2GiB"', 'tmp_max_age = "12h"'])
    write_workspace_container_config(workspace_dir, persistent=True)

    out = _run(coi_binary, workspace_dir, f"cat {ENV_FILE} {CONF_FILE}", args)
    assert f"TMP_MAX_BYTES={2 << 30}" in out and "root root 12h" in out, (
        f"restarted container should get 2GiB/12h. Output:\n{out}"
    )
