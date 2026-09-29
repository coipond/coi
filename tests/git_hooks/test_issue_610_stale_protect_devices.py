"""End-to-end regression tests for issue #610 — stale security disk devices must
not wedge a persistent container on restart, and protection must be re-established.

Background
----------
Coi protects security-sensitive paths by attaching one read-only Incus disk
device per path (``protect-husky``, ``protect-claude-settingsjson``, secret-mask
``mask-*`` and worktree ``gitc-*`` families) whose ``source=`` is a host path.
Incus validates every disk device's source at container **start**: a missing
source aborts the start with ``Missing source path``.

On a fresh launch the security setup materializes each source before attaching
the device, so it always exists. But that setup runs ONLY on a fresh launch. On
reuse/restart of a persistent container the creation-time devices keep their
original sources; if a source was removed from the workspace while the container
was stopped, the restart wedges and a fresh ``coi run`` never self-heals it
(issue #610).

The fix strips the workspace-sourced security devices (``protect-*``/``mask-*``/
``gitc-*``) and RE-RUNS the same validated security setup a fresh launch uses,
BEFORE start, on both restart seams (``coi run`` via a ``preRestart`` hook, and
``coi shell`` — see tests/shell/persistent/). Because it re-runs the fresh-launch
code, all the materialization / symlink-rejection / type / missing-path handling
comes from one place, and protection is re-established to match the CURRENT
workspace (paths added, removed, or replaced since first launch).

These tests drive the real ``coi run`` persistent flow. Each maps to a reviewed
failure mode:

- removed default dir / file / user path → restart must succeed (core wedge)
- protection re-established (write blocked, placeholder empty) after restart
- re-establishment after a removed path is later recreated
- source replaced by a dangling symlink → must not wedge (Lstat gate)
- parent directory replaced by a file (ENOTDIR) → must not wedge
- default dir replaced by a file (type drift) → must not wedge

Each test uses a unique workspace (pytest tmp_path) so container names never
collide even though slots repeat.
"""

import shutil
import subprocess
from pathlib import Path

from support.helpers import calculate_container_name, write_workspace_container_config

TIMEOUT = 180
READONLY_MARKERS = ("read-only", "read only", "permission denied")


def _run(coi_binary, workspace_dir, slot, *cmd):
    """Run one persistent ``coi run <cmd>`` in workspace_dir/slot."""
    return subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--slot", str(slot), *cmd],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )


def _first_persistent_run(coi_binary, workspace_dir, slot, marker):
    """First persistent run: materializes the default protected paths and leaves
    the container behind STOPPED. Asserts it exists AND is stopped, so the second
    run is guaranteed to hit the stopped-restart branch (the one the fix targets),
    not the running-reuse branch. Returns the container name.
    """
    result = _run(coi_binary, workspace_dir, slot, "echo", marker)
    assert result.returncode == 0, f"First persistent run should succeed. stderr: {result.stderr}"
    assert marker in (result.stdout + result.stderr), "First run should echo its marker"

    container_name = calculate_container_name(workspace_dir, slot)
    exists = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert exists.returncode == 0, "Persistent container should still exist after first run"

    # Must be STOPPED — otherwise the next run would reuse a RUNNING container (a
    # branch that deliberately does not reconcile), giving a false green.
    running = subprocess.run(
        [coi_binary, "container", "running", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert running.returncode != 0, (
        "Persistent container must be STOPPED between runs so the restart branch "
        f"(and its reconcile) is exercised. `container running` stdout: {running.stdout}"
    )
    return container_name


def _assert_restarted_ok(result, marker):
    """Assert a reuse run succeeded, took the stopped-restart branch, and did not
    hit the Incus start-validation wedge."""
    combined = result.stdout + result.stderr
    assert result.returncode == 0, f"Restart must succeed, not wedge. stderr:\n{combined}"
    assert marker in combined, "Reuse run should execute its command"
    assert "Missing source path" not in combined, (
        f"Incus rejected a stale security device at start:\n{combined}"
    )
    assert "Restarting existing persistent container" in combined, (
        "Reuse run must take the stopped-restart branch (where the reconcile runs), "
        f"not launch fresh or reuse a running container. stderr:\n{combined}"
    )


def _attempt_write(coi_binary, workspace_dir, slot, rel_path, marker="pwn"):
    """Attempt to write to a protected path from inside the container (itself a
    reuse run). Returns the CompletedProcess."""
    return _run(
        coi_binary,
        workspace_dir,
        slot,
        "--",
        "sh",
        "-c",
        f"echo {marker} > /workspace/{rel_path}",
    )


def _assert_write_blocked(result):
    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0, (
        "Write to a re-protected path must fail from inside the container"
    )
    assert any(m in combined for m in READONLY_MARKERS), (
        f"Expected a read-only/permission error, got:\n{result.stdout + result.stderr}"
    )


# --------------------------------------------------------------------------- #
# Core wedge: a removed source must not block the restart.
# --------------------------------------------------------------------------- #


def test_restart_after_removing_materialized_dir(coi_binary, cleanup_containers, workspace_dir):
    """Removed default DIRECTORY (.husky) → restart succeeds AND protection is
    re-established (dir re-materialized, write blocked). Covers the core #610
    wedge for a directory device."""
    slot = 3
    write_workspace_container_config(workspace_dir, persistent=True)
    _first_persistent_run(coi_binary, workspace_dir, slot, "first-husky")

    husky = Path(workspace_dir) / ".husky"
    assert husky.exists(), ".husky should have been materialized by the first run"
    shutil.rmtree(husky)

    _assert_restarted_ok(
        _run(coi_binary, workspace_dir, slot, "echo", "second-husky"), "second-husky"
    )

    # Protection re-established: re-materialized on the host...
    assert husky.exists() and husky.is_dir(), (
        ".husky must be re-materialized as a dir after restart"
    )
    # ...and read-only inside the container.
    _assert_write_blocked(_attempt_write(coi_binary, workspace_dir, slot, ".husky/pre-commit"))


def test_restart_after_removing_materialized_file(coi_binary, cleanup_containers, workspace_dir):
    """Removed default FILE (.claude/settings.json) → restart succeeds AND the
    placeholder is re-materialized EMPTY (anti-planting) and read-only. Covers the
    file-device wedge + the empty-placeholder guarantee (FLAWS Finding 2)."""
    slot = 4
    write_workspace_container_config(workspace_dir, persistent=True)
    _first_persistent_run(coi_binary, workspace_dir, slot, "first-claude")

    settings = Path(workspace_dir) / ".claude" / "settings.json"
    assert settings.exists(), ".claude/settings.json placeholder should have been materialized"
    settings.unlink()

    _assert_restarted_ok(
        _run(coi_binary, workspace_dir, slot, "echo", "second-claude"), "second-claude"
    )

    assert settings.exists() and settings.is_file(), ".claude/settings.json must be re-materialized"
    assert settings.read_text() == "", (
        f"re-materialized placeholder must be EMPTY (anti-planting), got: {settings.read_text()!r}"
    )
    _assert_write_blocked(_attempt_write(coi_binary, workspace_dir, slot, ".claude/settings.json"))


def test_restart_after_removing_user_additional_protected_path(
    coi_binary, cleanup_containers, workspace_dir
):
    """Removed user ``additional_protected_paths`` entry (.idea) → restart must
    succeed. The stale device is dropped (a user path that no longer exists is
    "nothing to protect", matching fresh-launch semantics) rather than wedging."""
    slot = 5
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(parents=True, exist_ok=True)
    (coi_dir / "config.toml").write_text('[security]\nadditional_protected_paths = [".idea"]\n')
    write_workspace_container_config(workspace_dir, persistent=True)

    idea = Path(workspace_dir) / ".idea"
    idea.mkdir()
    (idea / "workspace.xml").write_text("<project></project>")

    _first_persistent_run(coi_binary, workspace_dir, slot, "first-idea")
    shutil.rmtree(idea)

    _assert_restarted_ok(
        _run(coi_binary, workspace_dir, slot, "echo", "second-idea"), "second-idea"
    )


def test_protection_reestablished_after_restart(coi_binary, cleanup_containers, workspace_dir):
    """Removed default (.vscode) → after restart it must be re-materialized AND
    read-only inside, and an attacker write must not persist. Pins the full
    contract (re-establish protection, not just boot)."""
    slot = 6
    write_workspace_container_config(workspace_dir, persistent=True)
    _first_persistent_run(coi_binary, workspace_dir, slot, "first-vscode")

    vscode = Path(workspace_dir) / ".vscode"
    assert vscode.exists(), ".vscode should have been materialized by the first run"
    shutil.rmtree(vscode)

    _assert_restarted_ok(_run(coi_binary, workspace_dir, slot, "echo", "restart-ok"), "restart-ok")
    assert vscode.exists() and vscode.is_dir(), ".vscode must be re-materialized after restart"

    _assert_write_blocked(_attempt_write(coi_binary, workspace_dir, slot, ".vscode/tasks.json"))
    tasks_json = vscode / "tasks.json"
    assert not tasks_json.exists() or tasks_json.read_text() == "", (
        "attacker content must not persist to host .vscode"
    )


def test_protection_reestablished_after_recreate(coi_binary, cleanup_containers, workspace_dir):
    """Re-establishment across restarts: a user path removed (device dropped on
    restart A) and later RECREATED must be protected again on restart B. Guards
    the fix's re-run-every-restart property — a removed device is never
    permanently lost."""
    slot = 7
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(parents=True, exist_ok=True)
    (coi_dir / "config.toml").write_text('[security]\nadditional_protected_paths = [".idea"]\n')
    write_workspace_container_config(workspace_dir, persistent=True)

    idea = Path(workspace_dir) / ".idea"
    idea.mkdir()
    (idea / "workspace.xml").write_text("<project></project>")
    _first_persistent_run(coi_binary, workspace_dir, slot, "first-recreate")

    # Restart A: path gone → device dropped, container boots.
    shutil.rmtree(idea)
    _assert_restarted_ok(_run(coi_binary, workspace_dir, slot, "echo", "restartA"), "restartA")

    # Recreate the path on the host, then Restart B must re-protect it.
    idea.mkdir()
    (idea / "workspace.xml").write_text("<project></project>")
    _assert_write_blocked(_attempt_write(coi_binary, workspace_dir, slot, ".idea/workspace.xml"))
    assert (idea / "workspace.xml").read_text() == "<project></project>", (
        "recreated .idea content must be preserved (protected read-only), not overwritten"
    )


# --------------------------------------------------------------------------- #
# The staleness/validity of a source now comes from the fresh-launch primitives
# (strip + re-run), so a source replaced by a symlink, an ENOTDIR parent, or a
# wrong type must not wedge the restart.
# --------------------------------------------------------------------------- #


def test_restart_after_replacing_source_with_dangling_symlink(
    coi_binary, cleanup_containers, workspace_dir
):
    """Source replaced by a DANGLING SYMLINK → restart must not wedge. A plain
    Lstat 'exists' check would leave the stale device and Incus would still reject
    the resolved-missing target at start; the strip + re-run refuses the symlink
    (as fresh launch does) and starts cleanly."""
    slot = 8
    write_workspace_container_config(workspace_dir, persistent=True)
    _first_persistent_run(coi_binary, workspace_dir, slot, "first-symlink")

    vscode = Path(workspace_dir) / ".vscode"
    shutil.rmtree(vscode)
    vscode.symlink_to("does-not-exist")  # dangling symlink at the old source path

    _assert_restarted_ok(
        _run(coi_binary, workspace_dir, slot, "echo", "second-symlink"), "second-symlink"
    )


def test_restart_after_parent_directory_became_file(coi_binary, cleanup_containers, workspace_dir):
    """Parent of a protected file replaced by a regular file (ENOTDIR) → restart
    must not wedge. os.IsNotExist(ENOTDIR) is false, so a naive gate would keep
    the stale .claude/settings.json device and wedge; the fix re-runs setup, can't
    materialize under a file, and simply skips it — the container starts."""
    slot = 9
    write_workspace_container_config(workspace_dir, persistent=True)
    _first_persistent_run(coi_binary, workspace_dir, slot, "first-enotdir")

    claude = Path(workspace_dir) / ".claude"
    shutil.rmtree(claude)
    claude.write_text("not a directory")  # .claude is now a regular file

    _assert_restarted_ok(
        _run(coi_binary, workspace_dir, slot, "echo", "second-enotdir"), "second-enotdir"
    )


def test_restart_after_type_drift_dir_to_file(coi_binary, cleanup_containers, workspace_dir):
    """Default DIRECTORY source replaced by a FILE (type drift) → restart must not
    wedge. Existence-only checks would keep the device with a mismatched mount
    type; strip + re-run handles the current on-disk type."""
    slot = 10
    write_workspace_container_config(workspace_dir, persistent=True)
    _first_persistent_run(coi_binary, workspace_dir, slot, "first-typedrift")

    husky = Path(workspace_dir) / ".husky"
    shutil.rmtree(husky)
    husky.write_text("now a file")  # .husky is now a regular file

    _assert_restarted_ok(
        _run(coi_binary, workspace_dir, slot, "echo", "second-typedrift"), "second-typedrift"
    )
