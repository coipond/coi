"""
End-to-end tests for the `[git] protected_branches` guard.

coi installs root-owned pre-commit and pre-push hooks (via core.hooksPath) that
REJECT committing on, or pushing to, a protected branch — so an autonomous agent
works on feature branches, never main. The guard is on by default
(["main","master"]) and disableable with `protected_branches = []`.

These drive a real container (Incus on CI): launch a `coi shell`, create a
throwaway git repo inside it (the guard is global, so any repo is covered), and
assert both the NEGATIVE case (protected branch blocked) and the POSITIVE case
(feature branch allowed) for commit and push. A disabled-guard control proves the
hooks are what block, not some unrelated failure.
"""

import subprocess

from support.helpers import extract_container_name, write_trusted_coi_config

HOME = "/home/code"
REPO = "/tmp/guardrepo"
REMOTE = "/tmp/guardremote"

# One compound setup: a fresh repo on `main` with a local identity so commits
# don't trip useConfigOnly, a root commit, and one staged file ready to commit.
# The guard lets a new repo's root commit through (nothing to protect yet), so
# the setup succeeds with the guard on and the staged commit is the guarded one.
_SETUP = (
    f"rm -rf {REPO} {REMOTE} && mkdir -p {REPO} && cd {REPO} && "
    "git init -q && git symbolic-ref HEAD refs/heads/main && "
    "git config user.name t && git config user.email t@e && "
    "git commit -q --allow-empty -m root && "
    "echo hello > f.txt && git add f.txt"
)


def _start_background_shell(coi_binary, workspace_dir, env):
    result = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background", "--debug"],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 0, f"background shell should start. stderr: {result.stderr}"
    name = extract_container_name(result)
    assert name, f"could not find container name. stderr: {result.stderr}"
    return name


def _exec(coi_binary, name, script):
    """Run a shell snippet as the code user. `export HOME` (not a `HOME=x cmd`
    prefix) so the value survives the script's `&&` chains — a prefix assignment
    only applies to the first command, which would leave `git commit` reading the
    wrong HOME and missing the global core.hooksPath the guard lives at. coi
    container exec writes command output to stderr, so return combined + rc."""
    result = subprocess.run(
        [coi_binary, "container", "exec", name, "--", "sh", "-c", f"export HOME={HOME}; {script}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.returncode, (result.stdout + result.stderr)


def test_branch_guard_blocks_protected_allows_feature(
    coi_binary, workspace_dir, cleanup_containers
):
    """protected_branches = ["main"]: commit/push to main is rejected; the same
    work on a feature branch succeeds."""
    env = write_trusted_coi_config('[git]\nprotected_branches = ["main"]\n')
    name = _start_background_shell(coi_binary, workspace_dir, env)

    rc, out = _exec(coi_binary, name, _SETUP)
    assert rc == 0, f"repo setup failed: {out}"

    # NEGATIVE — commit on the protected branch is rejected with the guard message.
    rc, out = _exec(coi_binary, name, f"cd {REPO} && git commit -m 'on main'")
    assert rc != 0, f"commit on main should be rejected, got rc={rc}: {out}"
    assert "refusing to commit on protected branch 'main'" in out, (
        f"expected the branch-guard rejection, got: {out}"
    )

    # POSITIVE — the identical commit succeeds on a feature branch.
    rc, out = _exec(
        coi_binary, name, f"cd {REPO} && git checkout -q -b feature && git commit -m 'on feature'"
    )
    assert rc == 0, f"commit on a feature branch should succeed, got rc={rc}: {out}"

    # Wire up a bare remote for the push cases.
    rc, out = _exec(
        coi_binary,
        name,
        f"git init --bare -q {REMOTE} && cd {REPO} && git remote add origin {REMOTE}",
    )
    assert rc == 0, f"remote setup failed: {out}"

    # POSITIVE — pushing the feature branch (destination refs/heads/feature) is fine.
    rc, out = _exec(coi_binary, name, f"cd {REPO} && git push -q origin feature")
    assert rc == 0, f"pushing a feature branch should succeed, got rc={rc}: {out}"

    # NEGATIVE — pushing to the protected DESTINATION ref is rejected, even though
    # the local branch is 'feature' (the guard matches the remote ref, not local).
    rc, out = _exec(coi_binary, name, f"cd {REPO} && git push origin feature:main")
    assert rc != 0, f"push to main should be rejected, got rc={rc}: {out}"
    assert "refusing to push to protected branch 'main'" in out, (
        f"expected the push rejection, got: {out}"
    )


def test_branch_guard_disabled_allows_main(coi_binary, workspace_dir, cleanup_containers):
    """Control: protected_branches = [] disables the guard, so committing on main
    succeeds — proving the hooks (not something unrelated) are what block above."""
    env = write_trusted_coi_config("[git]\nprotected_branches = []\n")
    name = _start_background_shell(coi_binary, workspace_dir, env)

    rc, out = _exec(coi_binary, name, _SETUP)
    assert rc == 0, f"repo setup failed: {out}"

    rc, out = _exec(coi_binary, name, f"cd {REPO} && git commit -m 'on main'")
    assert rc == 0, f"with the guard disabled, a commit on main should succeed, got rc={rc}: {out}"
