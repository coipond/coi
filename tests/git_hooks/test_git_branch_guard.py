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

import os
import subprocess
from pathlib import Path

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


# Paths for the reference-transaction scenario: a bare "server", a seed repo
# that publishes main, a working clone, and a second clone that advances main.
RT_SERVER = "/tmp/rt-server.git"
RT_SEED = "/tmp/rt-seed"
RT_CLONE = "/tmp/rt-clone"
RT_OTHER = "/tmp/rt-other"
_ID = "git config user.name t && git config user.email t@e"
# Test-only bypass for SETUP steps that legitimately move main (the guard is
# global; a repo-local hooks path overriding it is a documented bypass).
_NOHOOKS = "git -c core.hooksPath=/dev/null"


def test_branch_guard_reference_transaction_paths(coi_binary, workspace_dir, cleanup_containers):
    """With coi's real installed hooks, the reference-transaction guard refuses
    the ways of moving main that never fire pre-commit (branch -f, cherry-pick),
    refuses `fetch origin main:main` with a working alternative, and leaves a new
    repo's first commit, creating main in a repo without remotes, and pushes
    INTO a local bare repository alone."""
    env = write_trusted_coi_config('[git]\nprotected_branches = ["main"]\n')
    name = _start_background_shell(coi_binary, workspace_dir, env)

    def ok(script, what):
        rc, out = _exec(coi_binary, name, script)
        assert rc == 0, f"{what} should succeed, got rc={rc}: {out}"
        return out

    def refused(script, what):
        rc, out = _exec(coi_binary, name, script)
        assert rc != 0, f"{what} should be refused, got rc={rc}: {out}"
        assert "refusing to move protected branch 'main'" in out, (
            f"{what}: expected the reference-transaction guard's message, got: {out}"
        )
        return out

    # A fresh repo's first commit is allowed; publishing it creates main in the
    # bare server, whose own receive side must not apply the guard.
    ok(
        f"rm -rf {RT_SERVER} {RT_SEED} {RT_CLONE} {RT_OTHER} && "
        f"git init -q --bare -b main {RT_SERVER} && "
        f"git init -q -b main {RT_SEED} && cd {RT_SEED} && {_ID} && "
        "echo base > base.txt && git add base.txt && git commit -q -m base && "
        f"git remote add origin {RT_SERVER} && git push -q --no-verify origin main",
        "first commit in a new repo + publishing it to a bare server",
    )

    # Working clone with a local-only commit on a feature branch.
    ok(
        f"git clone -q {RT_SERVER} {RT_CLONE} && cd {RT_CLONE} && {_ID} && "
        "git switch -q -c feature && echo f > f.txt && git add f.txt && git commit -q -m feat",
        "clone + feature-branch commit",
    )
    main_before = ok(f"cd {RT_CLONE} && git rev-parse main", "rev-parse").strip().splitlines()[-1]

    # Paths that never fire pre-commit must still be refused.
    refused(f"cd {RT_CLONE} && git branch -f main feature", "branch -f main <local commit>")
    refused(
        f"cd {RT_CLONE} && git switch -q main && git cherry-pick feature",
        "cherry-pick onto main",
    )
    _exec(
        coi_binary,
        name,
        f"cd {RT_CLONE} && git cherry-pick --abort; git reset -q --hard {main_before}; "
        "git switch -q feature",
    )

    # Advance main on the server from a second clone (setup only, hooks off),
    # pushing an UPDATE into the bare repo — its receive side must accept it.
    ok(
        f"git clone -q {RT_SERVER} {RT_OTHER} && cd {RT_OTHER} && {_ID} && "
        f"{_NOHOOKS} commit -q --allow-empty -m upstream && git push -q --no-verify origin main",
        "pushing an update into a local bare repository",
    )

    # `fetch origin main:main` moves main before origin/main, so it's refused —
    # with a message naming the alternative, which must work.
    out = refused(f"cd {RT_CLONE} && git fetch -q origin main:main", "fetch origin main:main")
    assert "git branch -f main <remote>/main" in out, f"refusal should name the alternative: {out}"
    ok(
        f"cd {RT_CLONE} && git fetch -q origin && git branch -f main origin/main && "
        'test "$(git rev-parse main)" = "$(git rev-parse origin/main)"',
        "the suggested alternative (git branch -f main origin/main)",
    )

    # A repo without remote-tracking refs may create main from existing work.
    ok(
        "rm -rf /tmp/rt-local && git init -q -b dev /tmp/rt-local && cd /tmp/rt-local && "
        f"{_ID} && git commit -q --allow-empty -m one && git commit -q --allow-empty -m two && "
        "git checkout -q -b main",
        "creating main in a repo with no remotes (git init -b dev, commits, checkout -b main)",
    )


def _write_profile(base_dir, name, body):
    """Write <base_dir>/profiles/<name>/config.toml and return its path."""
    path = Path(base_dir) / "profiles" / name / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def _trusted_profile_env(tmp_path, name, body):
    """A COI_CONFIG whose directory holds a profile: the directory of $COI_CONFIG
    is a trusted profile root (like ~/.coi), so this exercises a user's own
    profile without touching the runner's real ~/.coi."""
    cfg = tmp_path / "coi-config" / "config.toml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("")
    _write_profile(cfg.parent, name, body)
    return {**os.environ, "COI_CONFIG": str(cfg)}


def _start_profile_shell(coi_binary, workspace_dir, env, profile):
    result = subprocess.run(
        [
            coi_binary,
            "shell",
            "--workspace",
            workspace_dir,
            "--profile",
            profile,
            "--background",
            "--debug",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        # Run from the workspace, as a user would: project profiles are
        # discovered under <cwd>/.coi/profiles.
        cwd=workspace_dir,
    )
    assert result.returncode == 0, f"background shell should start. stderr: {result.stderr}"
    name = extract_container_name(result)
    assert name, f"could not find container name. stderr: {result.stderr}"
    return name, result


def test_branch_guard_list_from_profile(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """A user profile's [git] protected_branches replaces the default list: main
    becomes committable, the listed branch is guarded. (A profile containing the
    key used to fail schema validation and not load at all.)"""
    env = _trusted_profile_env(
        tmp_path, "guard-release", '[git]\nprotected_branches = ["release"]\n'
    )
    name, _ = _start_profile_shell(coi_binary, workspace_dir, env, "guard-release")

    rc, out = _exec(coi_binary, name, _SETUP)
    assert rc == 0, f"repo setup failed: {out}"

    rc, out = _exec(coi_binary, name, f"cd {REPO} && git commit -q -m 'on main'")
    assert rc == 0, f"main is not in the profile's list, so committing should work: {out}"

    rc, out = _exec(
        coi_binary,
        name,
        f"cd {REPO} && git checkout -q -b release && git commit -q --allow-empty -m 'on release'",
    )
    assert rc != 0, f"commit on release should be refused, got rc={rc}: {out}"
    assert "refusing to commit on protected branch 'release'" in out, out


def test_branch_guard_disabled_from_profile(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """A user profile's `protected_branches = []` disables the guard."""
    env = _trusted_profile_env(tmp_path, "guard-off", "[git]\nprotected_branches = []\n")
    name, _ = _start_profile_shell(coi_binary, workspace_dir, env, "guard-off")

    rc, out = _exec(coi_binary, name, _SETUP)
    assert rc == 0, f"repo setup failed: {out}"
    rc, out = _exec(coi_binary, name, f"cd {REPO} && git commit -q -m 'on main'")
    assert rc == 0, f"with the guard disabled by the profile, main should be committable: {out}"


def test_branch_guard_project_profile_cannot_disable(coi_binary, workspace_dir, cleanup_containers):
    """A repo's own profile (workspace .coi/profiles) can't change the list: its
    `[]` is ignored with a warning and main stays protected."""
    _write_profile(
        Path(workspace_dir) / ".coi", "repo-guard-off", "[git]\nprotected_branches = []\n"
    )
    name, result = _start_profile_shell(coi_binary, workspace_dir, {**os.environ}, "repo-guard-off")
    assert "git.protected_branches" in result.stderr, (
        f"expected a warning about the ignored project setting:\n{result.stderr}"
    )

    rc, out = _exec(coi_binary, name, _SETUP)
    assert rc == 0, f"repo setup failed: {out}"
    rc, out = _exec(coi_binary, name, f"cd {REPO} && git commit -q -m 'on main'")
    assert rc != 0, f"a project profile must not disable the guard, got rc={rc}: {out}"
    assert "refusing to commit on protected branch 'main'" in out, out
