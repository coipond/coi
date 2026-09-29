"""
`coi run` (no args) executes a workspace-root `coi-run` script. The 0.10 claim
(#559 A7): a `coi-run` *symlink* is followed only if it resolves INSIDE the
workspace — a target outside it passes the host stat but would not exist in the
container, so Coi fails fast host-side with an explanation. Unit-tested
(run_test.go); these are the missing end-to-end checks.
"""

import os
import subprocess
from pathlib import Path


def _run_noargs(coi_binary, workspace_dir, timeout=120):
    # No `--` command => run-script mode: Coi looks for workspace/coi-run.
    return subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_coi_run_symlink_escaping_workspace_fails_fast(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """A coi-run symlink whose target is OUTSIDE the workspace must abort host-side,
    before any container launch, and must never execute the target."""
    outside = tmp_path / "evil.sh"
    outside.write_text("#!/bin/sh\necho ESCAPED-SHOULD-NOT-RUN\n")
    outside.chmod(0o755)
    (Path(workspace_dir) / "coi-run").symlink_to(outside)  # absolute target outside ws

    r = _run_noargs(coi_binary, workspace_dir, timeout=45)
    combined = r.stdout + r.stderr
    assert r.returncode != 0, f"escaping symlink must fail fast.\n{combined}"
    assert "outside the workspace" in combined, f"expected the escape explanation.\n{combined}"
    assert "ESCAPED-SHOULD-NOT-RUN" not in combined, "the escaping target must not execute"


def test_coi_run_dangling_symlink_fails_fast(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """A coi-run symlink to a nonexistent target fails fast with a clear message."""
    (Path(workspace_dir) / "coi-run").symlink_to(tmp_path / "nope-does-not-exist")

    r = _run_noargs(coi_binary, workspace_dir, timeout=45)
    combined = (r.stdout + r.stderr).lower()
    assert r.returncode != 0, f"dangling symlink must fail.\n{combined}"
    assert "dangling" in combined or "resolve" in combined, (
        f"expected a dangling/resolve error.\n{combined}"
    )


def test_coi_run_symlink_inside_workspace_runs(coi_binary, cleanup_containers, workspace_dir):
    """A coi-run symlink to a target INSIDE the workspace is followed and executed.
    Must be a RELATIVE symlink so it also resolves inside the container's mount."""
    real = Path(workspace_dir) / "real-script.sh"
    real.write_text("#!/bin/sh\necho SYMLINK-INSIDE-OK\n")
    real.chmod(0o755)
    # Relative target: /workspace/coi-run -> real-script.sh resolves in-container too.
    os.symlink("real-script.sh", Path(workspace_dir) / "coi-run")

    r = _run_noargs(coi_binary, workspace_dir, timeout=180)
    combined = r.stdout + r.stderr
    assert r.returncode == 0, f"in-workspace symlink script should run.\n{combined}"
    assert "SYMLINK-INSIDE-OK" in combined, f"the linked script must execute.\n{combined}"
