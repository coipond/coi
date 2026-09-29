"""
End-to-end tests for the UNOVERRIDABLE commit identity under `[git] readonly`.

`[git] readonly` mounts ~/.gitconfig read-only, but a config file alone loses to
`git -c user.*`, `git commit --author=`, and an agent exporting its own GIT_*.
This exercises the two enforcement layers that close those holes, in a real
container:
  - Layer 1: container-level GIT_AUTHOR_*/GIT_COMMITTER_* env (beats `-c user.*`).
  - Layer 2: a root-owned post-commit re-stamp hook (corrects `--author=` and
    agent-exported GIT_*, and — being post-commit, not a verify hook — survives
    `--no-verify`).

Each test writes its OWN trusted `[git] name/email` and asserts commits carry
THAT identity, so "no divergence between sources" is structural (no magic value).
"""

import subprocess

from support.helpers import extract_container_name, write_trusted_coi_config

BOT_NAME = "coipond-coder[bot]"
BOT_EMAIL = "317930231+coipond-coder[bot]@users.noreply.github.com"
BOT = f"{BOT_NAME} <{BOT_EMAIL}>"
HOME = "/home/code"
REPO = "/tmp/idlock"


def _start_locked_shell(coi_binary, workspace_dir):
    # protected_branches = [] disables the on-by-default branch guard: these tests
    # commit on the repo's default branch (master) to exercise the identity lock,
    # not branch protection, so the guard must not block those commits.
    env = write_trusted_coi_config(
        f'[git]\nname = "{BOT_NAME}"\nemail = "{BOT_EMAIL}"\nreadonly = true\nprotected_branches = []\n'
    )
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


def _exec(coi_binary, name, script, shell="sh -c"):
    """Run a snippet with HOME=/home/code so git targets the mounted gitconfig.
    coi container exec writes command output to stderr; return (rc, combined)."""
    result = subprocess.run(
        [coi_binary, "container", "exec", name, "--", *shell.split(), f"HOME={HOME} {script}"],
        capture_output=True,
        text=True,
        timeout=45,
    )
    return result.returncode, (result.stdout + result.stderr)


def _author(coi_binary, name):
    rc, out = _exec(coi_binary, name, f"git -C {REPO} log -1 --format='%an <%ae>'")
    assert rc == 0, f"reading author failed: {out}"
    return out.strip()


def _committer(coi_binary, name):
    rc, out = _exec(coi_binary, name, f"git -C {REPO} log -1 --format='%cn <%ce>'")
    assert rc == 0, f"reading committer failed: {out}"
    return out.strip()


def test_commit_identity_is_unoverridable(coi_binary, workspace_dir, cleanup_containers):
    """The reported attack and its cousins are all defeated: plain commit, `-c`
    override, `--author=`, and `--no-verify --author=` all end up as the locked
    identity, for BOTH author and committer."""
    name = _start_locked_shell(coi_binary, workspace_dir)
    rc, out = _exec(coi_binary, name, f"git init -q {REPO}")
    assert rc == 0, f"git init failed: {out}"

    # 1. plain commit -> locked identity.
    rc, out = _exec(coi_binary, name, f"git -C {REPO} commit --allow-empty -q -m t1")
    assert rc == 0, f"commit failed: {out}"
    assert _author(coi_binary, name) == BOT, "plain commit author must be the locked identity"
    assert _committer(coi_binary, name) == BOT, "plain commit committer must be the locked identity"

    # 2. THE reported attack: `-c user.*` override is defeated by Layer 1 env.
    rc, out = _exec(
        coi_binary,
        name,
        f"git -C {REPO} -c user.name=Evil -c user.email=evil@x commit --allow-empty -q -m t2",
    )
    assert rc == 0, f"commit failed: {out}"
    assert _author(coi_binary, name) == BOT, "`-c user.*` override must not change the author"
    assert _committer(coi_binary, name) == BOT, "`-c user.*` override must not change the committer"

    # 3. `--author=` is corrected by Layer 2 (post-commit re-stamp).
    rc, out = _exec(
        coi_binary,
        name,
        f"git -C {REPO} commit --allow-empty --author='Evil <evil@x>' -q -m t3",
    )
    assert rc == 0, f"commit failed: {out}"
    assert _author(coi_binary, name) == BOT, "`--author=` must be re-stamped to the locked identity"
    assert _committer(coi_binary, name) == BOT

    # 4. `--no-verify --author=` is STILL corrected (post-commit isn't a verify hook).
    rc, out = _exec(
        coi_binary,
        name,
        f"git -C {REPO} commit --allow-empty --no-verify --author='Evil <evil@x>' -q -m t4",
    )
    assert rc == 0, f"commit failed: {out}"
    assert _author(coi_binary, name) == BOT, "`--no-verify --author=` must still be re-stamped"

    # 5. Spoofed NAME with the LOCKED email must ALSO be re-stamped (the guard
    # compares name, not just email — otherwise `Evil <bot-email>` would stick).
    rc, out = _exec(
        coi_binary,
        name,
        f"git -C {REPO} commit --allow-empty --author='Evil <{BOT_EMAIL}>' -q -m t5",
    )
    assert rc == 0, f"commit failed: {out}"
    assert _author(coi_binary, name) == BOT, (
        "a spoofed author name with the locked email must be re-stamped to the locked name"
    )


def test_git_identity_env_present_in_all_shell_types(coi_binary, workspace_dir, cleanup_containers):
    """The GIT_* env must reach every shell an agent might use — a bare `sh -c`
    and `bash -c` (non-login, the real tool-exec path) AND `bash -lc` (login) —
    which is why it's container-level `environment.*`, not /etc/profile.d."""
    name = _start_locked_shell(coi_binary, workspace_dir)
    for shell in ("sh -c", "bash -c", "bash -lc"):
        rc, out = _exec(coi_binary, name, 'printf "%s" "$GIT_AUTHOR_EMAIL"', shell=shell)
        assert rc == 0 and BOT_EMAIL in out, (
            f"GIT_AUTHOR_EMAIL must be set in `{shell}`, got rc={rc}: {out}"
        )
        rc, out = _exec(coi_binary, name, 'printf "%s" "$GIT_COMMITTER_EMAIL"', shell=shell)
        assert rc == 0 and BOT_EMAIL in out, (
            f"GIT_COMMITTER_EMAIL must be set in `{shell}`, got rc={rc}: {out}"
        )


def test_no_divergence_between_sources(coi_binary, workspace_dir, cleanup_containers):
    """The mounted gitconfig email, the injected GIT_AUTHOR_EMAIL, and the
    configured identity must all be identical."""
    name = _start_locked_shell(coi_binary, workspace_dir)
    rc, cfg = _exec(coi_binary, name, "git config --global --get user.email")
    assert rc == 0, cfg
    rc, envval = _exec(coi_binary, name, 'printf "%s" "$GIT_AUTHOR_EMAIL"')
    assert rc == 0, envval
    assert cfg.strip() == BOT_EMAIL, f"gitconfig email diverged: {cfg!r}"
    assert envval.strip() == BOT_EMAIL, f"GIT_AUTHOR_EMAIL diverged: {envval!r}"


def test_repo_post_commit_runs_once_on_corrected_commit(
    coi_binary, workspace_dir, cleanup_containers
):
    """The re-stamp amends the commit (which re-fires post-commit), so the
    repo's OWN post-commit must still run exactly once — on the corrected commit,
    not twice. A repo post-commit that appends a line proves single delegation."""
    name = _start_locked_shell(coi_binary, workspace_dir)
    rc, out = _exec(coi_binary, name, f"git init -q {REPO}")
    assert rc == 0, out
    # Install a repo-local post-commit that records each run.
    hook = (
        f"mkdir -p {REPO}/.git/hooks && "
        f"printf '#!/bin/sh\\necho ran >> {REPO}/hookruns\\n' > {REPO}/.git/hooks/post-commit && "
        f"chmod +x {REPO}/.git/hooks/post-commit"
    )
    rc, out = _exec(coi_binary, name, hook)
    assert rc == 0, f"installing repo hook failed: {out}"

    # A commit that WILL be re-stamped (author override).
    rc, out = _exec(
        coi_binary,
        name,
        f"git -C {REPO} commit --allow-empty --author='Evil <evil@x>' -q -m t",
    )
    assert rc == 0, f"commit failed: {out}"

    assert _author(coi_binary, name) == BOT, "commit must be re-stamped to the locked identity"
    rc, runs = _exec(coi_binary, name, f"wc -l < {REPO}/hookruns 2>/dev/null || echo 0")
    assert rc == 0, runs
    assert runs.strip() == "1", (
        f"repo post-commit must run exactly once (on the corrected commit), ran {runs.strip()} times"
    )
