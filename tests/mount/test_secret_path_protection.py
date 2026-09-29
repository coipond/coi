"""
Workspace secret-path masking must hide repo-local secrets from the agent.

`security.secret_paths` lists workspace-relative globs (e.g. `.env`, `*.pem`,
`secrets/**`). Coi masks each match inside the container by mounting an empty,
read-only file/dir over it, so the contained agent can neither READ its contents
(exfil protection) nor MODIFY it (tamper protection). The host file is untouched.
Issue #494.
"""

from pathlib import Path

from support.helpers import run_coi_in_workspace as _run

SECRET_ENV = "API_TOKEN=topsecret-do-not-leak"
SECRET_PEM = "-----BEGIN PRIVATE KEY-----leakme"
SECRET_DB = "db-password-leakme"


def _seed(workspace_dir):
    ws = Path(workspace_dir)
    (ws / ".env").write_text(SECRET_ENV + "\n")
    (ws / "deploy.pem").write_text(SECRET_PEM + "\n")
    secrets = ws / "secrets"
    secrets.mkdir(exist_ok=True)
    (secrets / "db.conf").write_text(SECRET_DB + "\n")
    # Project config requesting masking. secret_paths is additive, so it is
    # honored even from an (untrusted) project .coi/config.toml.
    coi = ws / ".coi"
    coi.mkdir(exist_ok=True)
    (coi / "config.toml").write_text('[security]\nsecret_paths = [".env", "*.pem", "secrets/**"]\n')


def test_secret_paths_hidden_from_agent(coi_binary, cleanup_containers, workspace_dir):
    """The agent reads EMPTY for masked files/dirs — never the secret content."""
    _seed(workspace_dir)

    # .env and *.pem are masked with an empty file: cat returns nothing.
    for path, secret in (
        ("/workspace/.env", "topsecret-do-not-leak"),
        ("/workspace/deploy.pem", "leakme"),
    ):
        r = _run(coi_binary, workspace_dir, ["cat", path])
        assert secret not in r.stdout and secret not in r.stderr, (
            f"masked {path} leaked its secret to the agent.\nstdout: {r.stdout}\nstderr: {r.stderr}"
        )

    # secrets/ is masked with an empty dir: it lists no entries (check the ls
    # stdout only — the masked file's name legitimately appears in a "No such
    # file" error, which actually proves it is hidden).
    ls = _run(coi_binary, workspace_dir, ["ls", "-A", "/workspace/secrets"])
    assert "db.conf" not in ls.stdout, (
        f"masked secrets/ should be empty but still lists db.conf.\nstdout: {ls.stdout!r}"
    )
    # and its secret content is unreadable ("db-password" is unique to the db secret).
    cat = _run(
        coi_binary,
        workspace_dir,
        ["sh", "-c", "cat /workspace/secrets/db.conf 2>/dev/null || true"],
    )
    assert "db-password" not in (cat.stdout + cat.stderr), (
        f"masked secrets/ leaked its secret content.\nstdout: {cat.stdout}\nstderr: {cat.stderr}"
    )


def test_secret_paths_readonly(coi_binary, cleanup_containers, workspace_dir):
    """Masked secret files cannot be modified (read-only mount)."""
    _seed(workspace_dir)

    modify = _run(
        coi_binary,
        workspace_dir,
        ["sh", "-c", "echo 'pwned' > /workspace/.env"],
    )
    combined = (modify.stdout + modify.stderr).lower()
    assert modify.returncode != 0 or "read-only" in combined, (
        f"writing a masked secret should fail (read-only).\n"
        f"returncode: {modify.returncode}\nstdout: {modify.stdout}\nstderr: {modify.stderr}"
    )


def test_secret_paths_host_file_untouched(coi_binary, cleanup_containers, workspace_dir):
    """Masking only affects the container view; the host secret is unchanged."""
    _seed(workspace_dir)

    # Run anything so masking is applied for a session.
    _run(coi_binary, workspace_dir, ["true"])

    # The real secret is still on the host (masking does not delete it).
    assert (Path(workspace_dir) / ".env").read_text().strip() == SECRET_ENV
    assert (Path(workspace_dir) / "secrets" / "db.conf").read_text().strip() == SECRET_DB


def test_secret_path_symlink_is_resolved_and_masked(coi_binary, cleanup_containers, workspace_dir):
    """A secret reached through a symlink is masked at its real target.

    A repo must not be able to evade masking by making the listed secret a
    symlink to another in-workspace file. Coi resolves the symlink and masks
    the real target, so reading EITHER the link or its target returns empty.
    """
    ws = Path(workspace_dir)
    shared = ws / "shared"
    shared.mkdir(exist_ok=True)
    (shared / "real.env").write_text(SECRET_ENV + "\n")
    # Relative symlink so it also resolves correctly inside the container.
    link = ws / "link.env"
    link.symlink_to(Path("shared") / "real.env")

    coi = ws / ".coi"
    coi.mkdir(exist_ok=True)
    (coi / "config.toml").write_text('[security]\nsecret_paths = ["link.env"]\n')

    # Reading through the link AND the resolved real file both return empty.
    for path in ("/workspace/link.env", "/workspace/shared/real.env"):
        r = _run(coi_binary, workspace_dir, ["cat", path])
        assert "topsecret-do-not-leak" not in (r.stdout + r.stderr), (
            f"symlinked secret leaked via {path}.\nstdout: {r.stdout}\nstderr: {r.stderr}"
        )

    # Host target is untouched.
    assert (shared / "real.env").read_text().strip() == SECRET_ENV
