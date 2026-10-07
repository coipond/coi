"""
End-to-end test for the untrusted-mount trust gate (`coi trust`).

A project .coi/config.toml is untrusted (it can come from a cloned repo). Mounts
it declares whose host path resolves outside the workspace are ignored at launch
until approved with `coi trust`, preventing a repo from bind-mounting host paths
(writable -> host code execution). Approval is pinned to a fingerprint of the
mounts, so changing them re-arms the gate. Trusted-scope config ($COI_CONFIG,
~/.coi) and in-workspace mounts are never gated.

conftest sets COI_TRUST_ALL=1 suite-wide so the many tests that use out-of-
workspace project mounts keep working; these tests run coi with that var removed
so the gate is active.
"""

import os
import pathlib
import subprocess

SENTINEL = "SENTINEL_5731"
CONTAINER_PATH = "/mnt/htest"


def env_gate_active():
    return {k: v for k, v in os.environ.items() if k != "COI_TRUST_ALL"}


def write_config(workspace_dir, host_dir, container=CONTAINER_PATH, readonly=False):
    config_dir = pathlib.Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    ro = "true" if readonly else "false"
    (config_dir / "config.toml").write_text(
        f'[[mounts.default]]\nhost = "{host_dir}"\ncontainer = "{container}"\nreadonly = {ro}\n'
    )


def make_host_dir(tmp_path):
    host = tmp_path / "outside"
    host.mkdir()
    (host / "sentinel.txt").write_text(SENTINEL)
    return host


TRUSTED_PREFIX = "Trusted out-of-workspace mounts, forwarded sockets, credential entries, and published ports from "


def trusted_sources(output):
    """The source files `coi trust` reported, one per "Trusted ... from <src>" line."""
    return [
        line[len(TRUSTED_PREFIX) :].strip()
        for line in output.splitlines()
        if line.startswith(TRUSTED_PREFIX)
    ]


def assert_trusted_exactly_workspace_config(t, workspace_dir):
    """`coi trust` must report exactly one source — this workspace's
    .coi/config.toml — and never an empty one (a spurious "" entry would also
    land in the trust store)."""
    sources = trusted_sources(t.stdout + t.stderr)
    expected = {
        str(pathlib.Path(workspace_dir) / ".coi" / "config.toml"),
        os.path.realpath(pathlib.Path(workspace_dir) / ".coi" / "config.toml"),
    }
    assert len(sources) == 1 and sources[0] in expected, (
        f"coi trust should report exactly the workspace config, got {sources!r}\n"
        f"output: {t.stdout}{t.stderr}"
    )


def probe(coi_binary, workspace_dir, env, container=CONTAINER_PATH):
    """Run `coi run` and read the sentinel through the (maybe-mounted) path."""
    return subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "sh",
            "-c",
            f"cat {container}/sentinel.txt 2>/dev/null || true",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
        env=env,
    )


def test_untrusted_escaping_mount_gated_until_trusted(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    host = make_host_dir(tmp_path)
    write_config(workspace_dir, host)
    env = env_gate_active()

    # 1. Untrusted + escaping -> gated: mount absent, warning emitted.
    r = probe(coi_binary, workspace_dir, env)
    assert SENTINEL not in r.stdout, f"mount should be gated, but sentinel present: {r.stdout}"
    assert "ignoring untrusted mount" in r.stderr.lower(), (
        f"expected the gate warning on stderr. stderr: {r.stderr}"
    )

    # 2. Approve it.
    t = subprocess.run(
        [coi_binary, "trust"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
        env=env,
    )
    assert t.returncode == 0, f"coi trust should succeed. stderr: {t.stderr}"
    assert_trusted_exactly_workspace_config(t, workspace_dir)
    assert "trusted" in (t.stdout + t.stderr).lower(), (
        f"unexpected trust output: {t.stdout}{t.stderr}"
    )

    # 3. Now the mount is present.
    r = probe(coi_binary, workspace_dir, env)
    assert SENTINEL in r.stdout, (
        f"mount should be present after trust. stdout: {r.stdout} stderr: {r.stderr}"
    )

    # 4. Changing the mounts re-arms the gate (fingerprint mismatch).
    write_config(workspace_dir, host, container="/mnt/htest2")
    r = probe(coi_binary, workspace_dir, env, container="/mnt/htest2")
    assert SENTINEL not in r.stdout, "changed mount must be re-gated until re-trusted"
    assert "ignoring untrusted mount" in r.stderr.lower()

    # 5. COI_TRUST_ALL bypass works even though untrusted.
    bypass = dict(env)
    bypass["COI_TRUST_ALL"] = "1"
    r = probe(coi_binary, workspace_dir, bypass, container="/mnt/htest2")
    assert SENTINEL in r.stdout, "COI_TRUST_ALL=1 should bypass the gate"


def test_coi_config_scope_mount_not_gated(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """A mount from a $COI_CONFIG (trusted-scope) config is never gated — the
    backend-builds-config-in-tmp / web-UI path."""
    host = make_host_dir(tmp_path)
    cfg_path = tmp_path / "trusted-config.toml"
    cfg_path.write_text(
        f'[[mounts.default]]\nhost = "{host}"\ncontainer = "{CONTAINER_PATH}"\nreadonly = false\n'
    )
    env = env_gate_active()
    env["COI_CONFIG"] = str(cfg_path)

    r = probe(coi_binary, workspace_dir, env)
    assert SENTINEL in r.stdout, (
        f"mount from $COI_CONFIG (trusted scope) must not be gated. "
        f"stdout: {r.stdout} stderr: {r.stderr}"
    )


def test_trust_list_and_untrust_roundtrip(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """trust -> mount present -> `trust --list` shows it -> untrust -> gated again."""
    host = make_host_dir(tmp_path)
    write_config(workspace_dir, host)
    env = env_gate_active()

    t = subprocess.run(
        [coi_binary, "trust"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
        env=env,
    )
    assert t.returncode == 0, f"trust failed: {t.stderr}"
    assert_trusted_exactly_workspace_config(t, workspace_dir)

    r = probe(coi_binary, workspace_dir, env)
    assert SENTINEL in r.stdout, "mount should be present after trust"

    listing = subprocess.run(
        [coi_binary, "trust", "--list"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
        env=env,
    )
    assert listing.returncode == 0
    assert "config.toml" in listing.stdout, f"trust --list should show the entry: {listing.stdout}"
    # Each line is "<fingerprint>  <path>". The store is shared with other tests
    # (same HOME), so count only this workspace's entry — exactly one — and
    # require that no entry anywhere has an empty path.
    entries = [line.split(None, 1) for line in listing.stdout.splitlines() if line.strip()]
    assert all(len(e) == 2 and e[1].strip() for e in entries), (
        f"trust --list must not contain an entry with an empty path:\n{listing.stdout}"
    )
    workspace_cfgs = {
        str(pathlib.Path(workspace_dir) / ".coi" / "config.toml"),
        os.path.realpath(pathlib.Path(workspace_dir) / ".coi" / "config.toml"),
    }
    mine = [e for e in entries if e[1].strip() in workspace_cfgs]
    assert len(mine) == 1, (
        f"trust --list should list this workspace's config exactly once:\n{listing.stdout}"
    )

    u = subprocess.run(
        [coi_binary, "untrust"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
        env=env,
    )
    assert u.returncode == 0, f"untrust failed: {u.stderr}"
    assert "revoked" in (u.stdout + u.stderr).lower(), (
        f"unexpected untrust output: {u.stdout}{u.stderr}"
    )

    r = probe(coi_binary, workspace_dir, env)
    assert SENTINEL not in r.stdout, "mount must be gated again after untrust"
    assert "ignoring untrusted mount" in r.stderr.lower()


def test_readonly_escaping_mount_gated(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """A read-only out-of-workspace mount still exfiltrates host data, so it is gated too."""
    host = make_host_dir(tmp_path)
    write_config(workspace_dir, host, readonly=True)
    env = env_gate_active()

    r = probe(coi_binary, workspace_dir, env)
    assert SENTINEL not in r.stdout, f"read-only escaping mount should be gated: {r.stdout}"
    assert "ignoring untrusted mount" in r.stderr.lower(), f"expected gate warning: {r.stderr}"


def test_project_scoped_profile_mount_gated(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """An escaping mount declared by a project-scoped PROFILE (./.coi/profiles/dev)
    is untrusted too — it must be gated, not silently mounted (the profile bypass
    of the H4 vector)."""
    host = make_host_dir(tmp_path)
    prof = pathlib.Path(workspace_dir) / ".coi" / "profiles" / "dev"
    prof.mkdir(parents=True)
    (prof / "config.toml").write_text(
        f'[[mounts]]\nhost = "{host}"\ncontainer = "{CONTAINER_PATH}"\nreadonly = false\n'
    )
    env = env_gate_active()

    r = subprocess.run(
        [
            coi_binary,
            "run",
            "--profile",
            "dev",
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
    assert SENTINEL not in r.stdout, (
        f"profile-declared escaping mount should be gated. stdout: {r.stdout} stderr: {r.stderr}"
    )
    assert "ignoring untrusted mount" in r.stderr.lower(), (
        f"expected the gate warning for the profile mount. stderr: {r.stderr}"
    )
