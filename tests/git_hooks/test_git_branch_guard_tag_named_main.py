"""
Test for the `[git] protected_branches` guard - a tag named like the branch.

With a tag `main` next to the branch `main`, `git symbolic-ref --short HEAD`
prints the disambiguated form `heads/main`, which an exact name match misses.
The guard must still see the branch as `main`.

Tests that:
1. In a repo on `main` with a tag also named `main`, `git commit` is refused
   with the guard message.
2. The same commit on a feature branch succeeds (the tag alone does not block).
"""

from git_hooks.test_git_branch_guard import _SETUP, REPO, _exec, _start_background_shell

from support.helpers import write_trusted_coi_config


def test_branch_guard_blocks_main_with_tag_named_main(
    coi_binary, workspace_dir, cleanup_containers
):
    """A tag named `main` does not let a commit on branch `main` through."""
    env = write_trusted_coi_config('[git]\nprotected_branches = ["main"]\n')
    name = _start_background_shell(coi_binary, workspace_dir, env)

    rc, out = _exec(coi_binary, name, f"{_SETUP} && git tag main")
    assert rc == 0, f"repo setup failed: {out}"

    rc, out = _exec(coi_binary, name, f"cd {REPO} && git commit -m 'on main'")
    assert rc != 0, f"commit on main with a tag named main should be rejected, got rc={rc}: {out}"
    assert "refusing to commit on protected branch 'main'" in out, (
        f"expected the branch-guard rejection, got: {out}"
    )

    rc, out = _exec(
        coi_binary, name, f"cd {REPO} && git checkout -q -b feature && git commit -m 'on feature'"
    )
    assert rc == 0, f"commit on a feature branch should succeed, got rc={rc}: {out}"
