"""
Test for coi run - a commondir naming another dir is kept, and coi warns.

git writes a commondir only in a linked worktree's admin dir. coi keeps an
existing commondir of a submodule or nested git dir as it is, mounts it
read-only and warns at launch.

Tests that:
- a commondir of a submodule git dir and of a nested repo that names another
  dir is kept on the host, cannot be written from the container, and the
  launch warns naming each one
- git-made layouts (a submodule, a nested repo and their linked worktrees) give
  no warning
"""

import subprocess
from pathlib import Path

from support.helpers import (
    GIT,
    init_repo_with_submodule,
    make_workspace_writable,
    run_coi_in_workspace,
)

WARNING = "Warning: unexpected git commondir, kept as it is; check it:"
GIT_DIRS = (".git/modules/lib", "nested/.git")


def _workspace(workspace_dir, tmp_path):
    """A repo with submodule lib and a nested repo with a commit."""
    init_repo_with_submodule(workspace_dir, tmp_path)
    nested = Path(workspace_dir) / "nested"
    nested.mkdir()
    for args in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "init"]):
        subprocess.run([*GIT, *args], cwd=nested, check=True, capture_output=True)
    return Path(workspace_dir)


def test_unexpected_commondir_kept_and_warned(
    coi_binary, workspace_dir, tmp_path, cleanup_containers
):
    """A commondir naming another dir is kept read-only and named in the warning."""
    ws = _workspace(workspace_dir, tmp_path)
    target = ws / "other"
    target.mkdir()
    planted = f"{target}\n"
    for git_dir in GIT_DIRS:
        (ws / git_dir / "commondir").write_text(planted)
    make_workspace_writable(workspace_dir)
    probe = "\n".join(
        f'if : >> /workspace/{d}/commondir; then echo "OK {d}"; else echo "ERR {d}"; fi'
        for d in GIT_DIRS
    )

    result = run_coi_in_workspace(coi_binary, workspace_dir, ["sh", "-c", probe], timeout=180)

    output = result.stdout + result.stderr
    assert result.returncode == 0, f"coi run failed: {output}"
    warnings = [line for line in result.stderr.splitlines() if WARNING in line]
    assert len(warnings) == 1, f"expected one commondir warning, got: {output}"
    for git_dir in GIT_DIRS:
        assert f"{git_dir}/commondir -> {target.resolve()}" in warnings[0], (
            f"warning must name {git_dir}/commondir: {warnings[0]}"
        )
        assert f"ERR {git_dir}" in output, f"{git_dir}/commondir must be read-only: {output}"
        assert (ws / git_dir / "commondir").read_text() == planted, f"{git_dir}/commondir changed"


def test_git_made_layout_no_commondir_warning(
    coi_binary, workspace_dir, tmp_path, cleanup_containers
):
    """A submodule, a nested repo and their linked worktrees give no warning."""
    ws = _workspace(workspace_dir, tmp_path)
    for repo, worktree in ((ws / "lib", ws / "libwt"), (ws / "nested", ws / "nestedwt")):
        subprocess.run(
            [*GIT, "worktree", "add", "-q", "--detach", str(worktree)],
            cwd=repo,
            check=True,
            capture_output=True,
        )
    assert (ws / ".git/modules/lib/worktrees/libwt/commondir").is_file()
    assert (ws / "nested/.git/worktrees/nestedwt/commondir").is_file()
    make_workspace_writable(workspace_dir)

    result = run_coi_in_workspace(coi_binary, workspace_dir, ["true"], timeout=180)

    output = result.stdout + result.stderr
    assert result.returncode == 0, f"coi run failed: {output}"
    assert "unexpected git commondir" not in output, f"unexpected warning: {output}"
