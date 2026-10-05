"""
A secret_paths entry that is a symlink pointing outside the workspace is
reported, not skipped silently (issue #494).

Its target isn't mounted into the container, so there is nothing to mask and
nothing to leak; coi warns that the entry isn't hidden, still starts the
session, and still masks the other secrets.
"""

from pathlib import Path

from support.helpers import run_coi_in_workspace as _run

SECRET_ENV = "API_TOKEN=topsecret-do-not-leak"
SECRET_PEM = "-----BEGIN PRIVATE KEY-----leakme"


def test_secret_path_symlink_outside_workspace_is_reported(
    coi_binary, cleanup_containers, workspace_dir
):
    """A listed secret that is a symlink pointing OUTSIDE the workspace is not
    masked, and coi says so instead of failing silently.

    Its target isn't mounted into the container, so there is nothing to mask
    (and nothing to leak); the user is warned that the entry isn't hidden, the
    session still starts, and the other secrets are still masked.
    """
    ws = Path(workspace_dir)
    outside = ws.parent / "outside-workspace"
    outside.mkdir(exist_ok=True)
    (outside / "secret").write_text(SECRET_PEM + "\n")
    (ws / "escape.pem").symlink_to(outside / "secret")
    (ws / ".env").write_text(SECRET_ENV + "\n")

    coi = ws / ".coi"
    coi.mkdir(exist_ok=True)
    (coi / "config.toml").write_text('[security]\nsecret_paths = ["escape.pem", ".env"]\n')

    r = _run(
        coi_binary,
        workspace_dir,
        ["sh", "-c", "cat /workspace/escape.pem 2>&1; cat /workspace/.env"],
    )
    assert r.returncode == 0, f"the session should still start.\nstderr: {r.stderr}"
    assert 'secret_paths entry "escape.pem" is NOT masked' in r.stderr, (
        f"an unmaskable secret must be reported, not skipped silently.\nstderr: {r.stderr}"
    )
    assert "Masked secret paths (hidden read-only): .env" in r.stderr, (
        f"only .env should be masked; escape.pem must not be.\nstderr: {r.stderr}"
    )
    # Neither secret is readable: the link's target isn't in the container,
    # and .env is masked.
    assert "leakme" not in r.stdout and "topsecret-do-not-leak" not in r.stdout, (
        f"a secret leaked into the container.\nstdout: {r.stdout}"
    )
