"""
Protect the git config/attribute sinks that can drive host code execution.

git runs filter/diff/textconv driver commands (and core.hooksPath) defined in
git *config* files, named via *attributes* files, during routine operations
(checkout/status/diff). Coi already mounts .git/config and .git/hooks read-only;
these tests cover the remaining sinks:

- .git/info/attributes  — names drivers
- .git/config.worktree  — per-repo worktree config (read when extensions.worktreeConfig=true)
- .git/worktrees/<name>/config.worktree — per-worktree config (same)

If a container could write any of these, it could plant/define a driver that
runs on the host at the next git operation. They must be read-only.
"""

import subprocess
from pathlib import Path

import pytest


def _write_blocked(coi_binary, workspace_dir, container_path):
    """Attempt to append to container_path from inside the container; return CompletedProcess."""
    return subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            f"echo '[core]' >> {container_path}",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )


def _assert_blocked(result, host_file, original):
    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0, f"write should have failed; got rc=0. output: {combined}"
    assert "read-only" in combined or "read only" in combined or "permission denied" in combined, (
        f"expected read-only/permission error, got: {combined}"
    )
    assert host_file.read_text() == original, "host file must be unchanged"


def test_git_info_attributes_readonly(coi_binary, workspace_dir, cleanup_containers):
    """.git/info/attributes must be read-only (it names filter/diff/textconv drivers)."""
    subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)
    attrs = Path(workspace_dir) / ".git" / "info" / "attributes"
    original = "* text=auto\n"
    attrs.write_text(original)

    result = _write_blocked(coi_binary, workspace_dir, "/workspace/.git/info/attributes")
    _assert_blocked(result, attrs, original)


def test_git_config_worktree_readonly(coi_binary, workspace_dir, cleanup_containers):
    """.git/config.worktree must be read-only (a config sink under worktreeConfig)."""
    subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)
    cw = Path(workspace_dir) / ".git" / "config.worktree"
    original = "# worktree config\n"
    cw.write_text(original)

    result = _write_blocked(coi_binary, workspace_dir, "/workspace/.git/config.worktree")
    _assert_blocked(result, cw, original)


def _init_worktree_repo(workspace_dir):
    """git init + enable worktreeConfig; returns the base git command prefix. Skips on failure."""
    git = ["git", "-C", workspace_dir, "-c", "user.email=t@t", "-c", "user.name=t"]
    try:
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)
        subprocess.run(
            [*git, "commit", "--allow-empty", "-m", "init"], check=True, capture_output=True
        )
        subprocess.run(
            [*git, "config", "extensions.worktreeConfig", "true"], check=True, capture_output=True
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"git worktree setup unavailable: {e.stderr.decode(errors='replace')}")
    return git


def _add_worktree_with_config(git, workspace_dir, name):
    """Add a linked worktree <name> and create its per-worktree config.worktree.

    Returns the host Path to .git/worktrees/<name>/config.worktree, or skips if git
    did not produce it.
    """
    wt_path = str(Path(workspace_dir) / name)
    try:
        subprocess.run([*git, "worktree", "add", wt_path], check=True, capture_output=True)
        # Create the per-worktree config file (requires worktreeConfig).
        subprocess.run(
            ["git", "-C", wt_path, "config", "--worktree", "filter.evil.smudge", "id"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"git worktree setup unavailable: {e.stderr.decode(errors='replace')}")
    # git accepted `worktree add` + `config --worktree`, so it supports worktreeConfig.
    # If the per-worktree config file is nonetheless absent, our test assumption is
    # broken — fail loudly rather than skip (a silent skip would report green while
    # exercising nothing, masking a real ExpandGitWorktreeProtectedPaths regression).
    cw = Path(workspace_dir) / ".git" / "worktrees" / name / "config.worktree"
    if not cw.exists():
        pytest.fail(
            f"git config --worktree succeeded but {cw} was not created — "
            "test assumption broken (cannot verify protection)"
        )
    return cw


def test_per_worktree_config_readonly(coi_binary, workspace_dir, cleanup_containers):
    """.git/worktrees/<name>/config.worktree must be read-only (the reproduced M2 sink, #542)."""
    git = _init_worktree_repo(workspace_dir)
    cw = _add_worktree_with_config(git, workspace_dir, "wt")
    original = cw.read_text()

    result = _write_blocked(
        coi_binary, workspace_dir, "/workspace/.git/worktrees/wt/config.worktree"
    )
    _assert_blocked(result, cw, original)


def test_multiple_per_worktree_configs_readonly(coi_binary, workspace_dir, cleanup_containers):
    """Every per-worktree config is protected — the expansion must cover all worktrees,
    not just the first (#542). Regression guard for a single-entry expansion."""
    git = _init_worktree_repo(workspace_dir)
    cw_a = _add_worktree_with_config(git, workspace_dir, "wt_a")
    cw_b = _add_worktree_with_config(git, workspace_dir, "wt_b")
    original_a, original_b = cw_a.read_text(), cw_b.read_text()

    result_a = _write_blocked(
        coi_binary, workspace_dir, "/workspace/.git/worktrees/wt_a/config.worktree"
    )
    _assert_blocked(result_a, cw_a, original_a)

    result_b = _write_blocked(
        coi_binary, workspace_dir, "/workspace/.git/worktrees/wt_b/config.worktree"
    )
    _assert_blocked(result_b, cw_b, original_b)
