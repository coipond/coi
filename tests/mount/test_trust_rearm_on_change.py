"""
Changing any entry of a trusted source re-arms the trust gate for the WHOLE source.

`coi trust` records one fingerprint per project config covering every
host-affecting entry it declares (mounts, sockets, credentials incl. mode,
ports). A later change to ANY of them must gate the source again until it is
re-approved — not just the changed entry: approving a config approves it as a
whole. Unit-tested in internal/session/trust_test.go
(TestTrust_CombinedMountSocketAndCredentialSource); this covers the same
scenario end to end through the CLI.

conftest sets COI_TRUST_ALL=1 suite-wide; these tests remove it so the gate is
armed.
"""

import os
import pathlib
import subprocess

MOUNT_SENTINEL = "SENTINEL_REARM_MOUNT_51c7"
CRED_SENTINEL = "SENTINEL_REARM_CRED_51c7"
MOUNT_PATH = "/mnt/rearm"
CRED_PATH = "/home/code/.coi-rearm-cred"


def env_gate_active():
    return {k: v for k, v in os.environ.items() if k != "COI_TRUST_ALL"}


def write_config(workspace_dir, host_dir, cred_file, cred_mode):
    d = pathlib.Path(workspace_dir) / ".coi"
    d.mkdir(exist_ok=True)
    (d / "config.toml").write_text(
        f'[[mounts.default]]\nhost = "{host_dir}"\ncontainer = "{MOUNT_PATH}"\nreadonly = true\n\n'
        f'[[credentials]]\nhost = "{cred_file}"\ncontainer = "{CRED_PATH}"\nmode = "{cred_mode}"\n'
    )


def probe(coi_binary, workspace_dir, env):
    """Read both sentinels through the (maybe-applied) mount and credential."""
    return subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "sh",
            "-c",
            f"cat {MOUNT_PATH}/sentinel.txt 2>/dev/null; echo; cat {CRED_PATH} 2>/dev/null; true",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
        env=env,
    )


def trust(coi_binary, workspace_dir, env):
    t = subprocess.run(
        [coi_binary, "trust"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
        env=env,
    )
    assert t.returncode == 0, f"coi trust failed: {t.stdout}{t.stderr}"


def test_credential_change_regates_whole_source(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    host = tmp_path / "outside"
    host.mkdir()
    (host / "sentinel.txt").write_text(MOUNT_SENTINEL)
    cred = tmp_path / "rearm-cred.txt"
    cred.write_text(CRED_SENTINEL)
    env = env_gate_active()

    # 1. Untrusted: neither the mount nor the credential is applied.
    write_config(workspace_dir, host, cred, "0600")
    r = probe(coi_binary, workspace_dir, env)
    assert r.returncode == 0, f"coi run failed: {r.stderr}"
    assert MOUNT_SENTINEL not in r.stdout and CRED_SENTINEL not in r.stdout, (
        f"both entries must be gated before trust. stdout: {r.stdout}"
    )

    # 2. Approved: both are applied.
    trust(coi_binary, workspace_dir, env)
    r = probe(coi_binary, workspace_dir, env)
    assert MOUNT_SENTINEL in r.stdout and CRED_SENTINEL in r.stdout, (
        f"both entries must apply after `coi trust`. stdout: {r.stdout} stderr: {r.stderr}"
    )

    # 3. Change ONLY the credential's mode: the source's fingerprint changes, so
    #    the whole source is gated again — the unchanged mount included.
    write_config(workspace_dir, host, cred, "0644")
    r = probe(coi_binary, workspace_dir, env)
    assert r.returncode == 0, f"coi run failed: {r.stderr}"
    assert MOUNT_SENTINEL not in r.stdout, (
        f"a credential change must re-gate the source's mount too. stdout: {r.stdout}"
    )
    assert CRED_SENTINEL not in r.stdout, (
        f"the changed credential must be re-gated. stdout: {r.stdout}"
    )
    assert "ignoring untrusted mount" in r.stderr.lower(), (
        f"expected the mount gate warning after the change. stderr: {r.stderr}"
    )

    # 4. Re-approval applies the changed config again.
    trust(coi_binary, workspace_dir, env)
    r = probe(coi_binary, workspace_dir, env)
    assert MOUNT_SENTINEL in r.stdout and CRED_SENTINEL in r.stdout, (
        f"both entries must apply after re-trusting. stdout: {r.stdout} stderr: {r.stderr}"
    )
