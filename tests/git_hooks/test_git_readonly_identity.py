"""
End-to-end tests for `[git] readonly` (PR #711).

`[git] name/email` writes the container's global ~/.gitconfig, but that file is
writable, so an in-container agent can `git config --global user.name …` right
over it. `[git] readonly = true` mounts the identity READ-ONLY at ~/.gitconfig,
so the overwrite must fail on a read-only filesystem instead of silently winning.

These drive a real container (Incus available on CI): launch a `coi shell`, read
the installed identity, attempt to overwrite it, and assert the write fails and
the identity is unchanged. The writable control proves the lock is what blocks it.
"""

import subprocess

from support.helpers import start_background_shell, write_trusted_coi_config

BOT_NAME = "coipond-coder[bot]"
BOT_EMAIL = "317930231+coipond-coder[bot]@users.noreply.github.com"
HOME = "/home/code"


def _exec(coi_binary, name, script):
    """Run a shell snippet as the code user (HOME=/home/code, so git config
    --global targets the mounted ~/.gitconfig). coi container exec writes command
    output to stderr, so return the combined text plus the exit code."""
    result = subprocess.run(
        [coi_binary, "container", "exec", name, "--", "sh", "-c", f"HOME={HOME} {script}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode, (result.stdout + result.stderr)


def test_git_readonly_locks_identity(coi_binary, workspace_dir, cleanup_containers):
    """readonly = true: the identity is installed, and the agent cannot change it."""
    env = write_trusted_coi_config(
        f'[git]\nname = "{BOT_NAME}"\nemail = "{BOT_EMAIL}"\nreadonly = true\n'
    )
    name, _ = start_background_shell(coi_binary, workspace_dir, env)

    # The configured identity is in place.
    rc, out = _exec(coi_binary, name, "git config --global --get user.name")
    assert rc == 0 and BOT_NAME in out, (
        f"expected the pinned name to be installed, got rc={rc}: {out}"
    )
    rc, out = _exec(coi_binary, name, "git config --global --get user.email")
    assert rc == 0 and BOT_EMAIL in out, (
        f"expected the pinned email to be installed, got rc={rc}: {out}"
    )

    # The agent's attempt to overwrite it must FAIL. git config writes via
    # lock-file + rename, so a read-only ~/.gitconfig mount surfaces as one of a
    # few kernel errors (EROFS / EBUSY renaming over a mount point / EPERM); the
    # non-zero exit and the unchanged identity below are the real proof.
    rc, out = _exec(coi_binary, name, 'git config --global user.name "attacker"')
    assert rc != 0, (
        f"git config --global must fail against the read-only ~/.gitconfig, got rc={rc}: {out}"
    )
    lowered = out.lower()
    assert any(
        m in lowered for m in ("read-only", "read only", "busy", "permission denied", "cannot")
    ), f"the failure should be a filesystem write error, got: {out}"

    # ...and the identity is unchanged after the attempt.
    rc, out = _exec(coi_binary, name, "git config --global --get user.name")
    assert rc == 0 and BOT_NAME in out and "attacker" not in out, (
        f"identity must survive the overwrite attempt, got rc={rc}: {out}"
    )


def test_git_writable_control_can_be_overwritten(coi_binary, workspace_dir, cleanup_containers):
    """Control: WITHOUT readonly, the same overwrite succeeds — proving the lock in
    the test above is what blocks it, not some unrelated failure."""
    env = write_trusted_coi_config(
        f'[git]\nname = "{BOT_NAME}"\nemail = "{BOT_EMAIL}"\n'
        # readonly not set (default false → writable ~/.gitconfig)
    )
    name, _ = start_background_shell(coi_binary, workspace_dir, env)

    rc, out = _exec(coi_binary, name, "git config --global --get user.name")
    assert rc == 0 and BOT_NAME in out, f"expected the pinned name, got rc={rc}: {out}"

    rc, out = _exec(coi_binary, name, 'git config --global user.name "attacker"')
    assert rc == 0, f"without readonly the overwrite should succeed, got rc={rc}: {out}"

    rc, out = _exec(coi_binary, name, "git config --global --get user.name")
    assert rc == 0 and "attacker" in out, (
        f"without readonly the identity is writable and should now be 'attacker', got rc={rc}: {out}"
    )
