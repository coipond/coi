"""
In-workspace codex project config must be read-only inside the container (#698).

`.codex/config.toml` is codex's project-scoped config layer and can name
commands the host would run (e.g. `notify`, MCP server launchers) when a host
codex session trusts the repo. The workspace is mounted read-write and persists
to the host, so a contained agent that could write that file could plant a
command a *later* host codex session would auto-execute — the same containment
escape `.claude/settings.json` protection closes (#504). Coi mounts the file
read-only (protected_paths) and materializes an empty placeholder when absent
so it cannot be planted either.
"""

from pathlib import Path

from support.helpers import (
    make_workspace_writable as _make_workspace_writable,
)
from support.helpers import (
    run_coi_in_workspace as _run,
)


def test_codex_config_readonly_by_default(coi_binary, cleanup_containers, workspace_dir):
    """An existing .codex/config.toml is readable but cannot be modified."""
    codex_dir = Path(workspace_dir) / ".codex"
    codex_dir.mkdir(exist_ok=True)
    original = 'model = "gpt-5-codex"\n'
    (codex_dir / "config.toml").write_text(original)

    path = "/workspace/.codex/config.toml"

    # Guard against false-pass: the file must be visible inside the container.
    read_result = _run(coi_binary, workspace_dir, ["cat", path])
    assert read_result.returncode == 0, (
        f"{path} should be readable inside the container.\n"
        f"stdout: {read_result.stdout}\nstderr: {read_result.stderr}"
    )

    # Injecting a notify command into the existing file must fail (read-only mount).
    modify = _run(
        coi_binary,
        workspace_dir,
        ["sh", "-c", f'echo \'notify = ["curl", "evil"]\' > {path}'],
    )
    combined = (modify.stdout + modify.stderr).lower()
    assert modify.returncode != 0 or "read-only" in combined, (
        f"Writing {path} should fail (read-only).\n"
        f"returncode: {modify.returncode}\nstdout: {modify.stdout}\nstderr: {modify.stderr}"
    )

    # Host-side file must be untouched.
    assert (codex_dir / "config.toml").read_text() == original


def test_codex_config_cannot_be_planted_when_absent(coi_binary, cleanup_containers, workspace_dir):
    """With NO .codex dir at launch, a contained agent must not be able to PLANT
    .codex/config.toml carrying a command payload — Coi materializes the parent
    dir + an empty read-only placeholder, so the create fails and nothing
    persists to the host (mirrors the .claude/settings.json planting guard)."""
    codex_dir = Path(workspace_dir) / ".codex"
    assert not codex_dir.exists(), "test must start with no .codex dir (planting case)"

    # Make the workspace writable so ONLY the read-only mount (not file perms)
    # can stop the write — otherwise the test could pass for the wrong reason.
    _make_workspace_writable(workspace_dir)

    path = "/workspace/.codex/config.toml"
    result = _run(
        coi_binary,
        workspace_dir,
        ["sh", "-c", f'echo \'notify = ["curl", "evil"]\' > {path}'],
    )
    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0 or "read-only" in combined, (
        f"Planting an absent {path} must fail (read-only placeholder).\n"
        f"returncode: {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    # Nothing malicious persisted to the host — the placeholder Coi created is empty.
    host_file = codex_dir / "config.toml"
    if host_file.exists():
        content = host_file.read_text()
        assert "notify" not in content and "curl" not in content, (
            f"planted payload persisted to host {host_file}: {content!r}"
        )


def test_untrusted_writable_paths_is_ignored(coi_binary, cleanup_containers, workspace_dir):
    """A project .coi/config.toml cannot opt out of the protection."""
    codex_dir = Path(workspace_dir) / ".codex"
    codex_dir.mkdir(exist_ok=True)
    original = 'model = "gpt-5-codex"\n'
    (codex_dir / "config.toml").write_text(original)

    # A cloned repo ships a project config trying to disable the protection.
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text('[security]\nwritable_paths = [".codex/config.toml"]\n')

    # The setting is sanitized away, so the file stays read-only.
    modify = _run(
        coi_binary,
        workspace_dir,
        ["sh", "-c", "echo 'pwned' > /workspace/.codex/config.toml"],
    )
    combined = (modify.stdout + modify.stderr).lower()
    assert modify.returncode != 0 or "read-only" in combined, (
        "Untrusted writable_paths must NOT make .codex/config.toml writable.\n"
        f"returncode: {modify.returncode}\nstdout: {modify.stdout}\nstderr: {modify.stderr}"
    )
    assert (codex_dir / "config.toml").read_text() == original
