"""
Trust-gate e2e coverage for a project mount that escapes the workspace through a symlink.

A project .coi/config.toml mount whose host path is lexically inside the
workspace, but is a symlink to a directory outside it, must be gated like any
other escaping mount: Incus follows the link at mount time, so a lexical check
would let a cloned repo bind-mount arbitrary host paths. The gate resolves
symlinks (internal/session/trust.go realPath); a mount really inside the
workspace stays ungated.

conftest sets COI_TRUST_ALL=1 suite-wide; these tests remove it so the gate is
armed.
"""

import os
import pathlib
import subprocess

SENTINEL = "SENTINEL_SYMLINK_GATE_4e2a"
CONTAINER_PATH = "/mnt/symlinkgate"


def env_gate_active():
    return {k: v for k, v in os.environ.items() if k != "COI_TRUST_ALL"}


def write_config(workspace_dir, host_dir):
    d = pathlib.Path(workspace_dir) / ".coi"
    d.mkdir(exist_ok=True)
    (d / "config.toml").write_text(
        f'[[mounts.default]]\nhost = "{host_dir}"\ncontainer = "{CONTAINER_PATH}"\nreadonly = false\n'
    )


def probe(coi_binary, workspace_dir, env):
    """Run `coi run` and read the sentinel through the (maybe-mounted) path."""
    return subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "sh",
            "-c",
            f"cat {CONTAINER_PATH}/sentinel.txt 2>/dev/null || true",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
        env=env,
    )


def test_symlink_escaping_mount_gated_until_trusted(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """A mount via an in-workspace symlink to an outside dir is gated until `coi trust`."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel.txt").write_text(SENTINEL)
    link = pathlib.Path(workspace_dir) / "link"
    link.symlink_to(outside, target_is_directory=True)
    write_config(workspace_dir, link)
    env = env_gate_active()

    # 1. Untrusted: the symlinked mount is held back with a warning.
    r = probe(coi_binary, workspace_dir, env)
    assert r.returncode == 0, f"coi run failed: {r.stderr}"
    assert SENTINEL not in r.stdout, (
        f"a mount escaping through a symlink must be gated. stdout: {r.stdout}"
    )
    assert "ignoring untrusted mount" in r.stderr.lower(), (
        f"expected the gate warning on stderr. stderr: {r.stderr}"
    )

    # 2. Approved: the mount is applied.
    t = subprocess.run(
        [coi_binary, "trust"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
        env=env,
    )
    assert t.returncode == 0, f"coi trust failed: {t.stdout}{t.stderr}"
    r = probe(coi_binary, workspace_dir, env)
    assert SENTINEL in r.stdout, (
        f"the mount must apply after `coi trust`. stdout: {r.stdout} stderr: {r.stderr}"
    )


def test_in_workspace_mount_not_gated(coi_binary, workspace_dir, cleanup_containers):
    """A mount whose host path really is inside the workspace is applied without `coi trust`."""
    inside = pathlib.Path(workspace_dir) / "inside"
    inside.mkdir()
    (inside / "sentinel.txt").write_text(SENTINEL)
    write_config(workspace_dir, inside)

    r = probe(coi_binary, workspace_dir, env_gate_active())
    assert r.returncode == 0, f"coi run failed: {r.stderr}"
    assert "ignoring untrusted mount" not in r.stderr.lower(), (
        f"an in-workspace mount must not be gated. stderr: {r.stderr}"
    )
    assert SENTINEL in r.stdout, (
        f"an in-workspace mount must be applied. stdout: {r.stdout} stderr: {r.stderr}"
    )
