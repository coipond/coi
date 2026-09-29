"""
Non-sudoers mode: `[network] use_sudo = false` lets Coi run without the
installer's passwordless-sudo rule (/etc/sudoers.d/coi-nft). Issue #508.

When use_sudo=false Coi never invokes sudo for network ops, so it behaves as if
passwordless sudo were unavailable — regardless of whether the host actually has
sudo. That makes these tests real even on CI runners that DO have blanket sudo:
the config flag (not the environment) drives the behavior.

Expected behavior:
- open mode + use_sudo=false  -> runs fine (no privileged rules needed)
- restricted/allowlist + use_sudo=false -> fails with a clear, actionable error
  (they cannot be enforced without sudo; no silent downgrade to open)
- `coi health` reports nft as OK (open) / warning (restricted) — never a hard
  failure — when use_sudo=false

`mode = "open"` is sanitized out of an untrusted project .coi/config.toml, so the
network config is supplied via a trusted $COI_CONFIG file.
"""

import json
import os
import subprocess
from pathlib import Path

SENTINEL = "NO_SUDO_OK_7731"


def _trusted_config(tmp_path, body):
    cfg = Path(tmp_path) / "trusted-config.toml"
    cfg.write_text(body)
    env = dict(os.environ)
    env["COI_CONFIG"] = str(cfg)
    return env


def _run(coi_binary, workspace_dir, env, argv, timeout=120):
    return subprocess.run(
        [coi_binary, "run", "--", *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=workspace_dir,
        env=env,
    )


def test_open_mode_runs_without_sudo(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """open + use_sudo=false: container runs end-to-end, no sudo needed."""
    env = _trusted_config(tmp_path, '[network]\nmode = "open"\nuse_sudo = false\n')
    r = _run(coi_binary, workspace_dir, env, ["echo", SENTINEL])
    assert r.returncode == 0, (
        f"open + use_sudo=false should run without sudo. out={r.stdout} err={r.stderr}"
    )
    assert SENTINEL in r.stdout, f"expected command output. out={r.stdout} err={r.stderr}"


def test_restricted_mode_fails_clearly_without_sudo(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """restricted + use_sudo=false: aborts with an actionable error (no silent downgrade)."""
    env = _trusted_config(tmp_path, '[network]\nmode = "restricted"\nuse_sudo = false\n')
    r = _run(coi_binary, workspace_dir, env, ["echo", SENTINEL])
    assert r.returncode != 0, (
        f"restricted + use_sudo=false must fail (cannot enforce without sudo). "
        f"out={r.stdout} err={r.stderr}"
    )
    assert SENTINEL not in r.stdout, "container must not run when isolation can't be enforced"
    combined = (r.stdout + r.stderr).lower()
    assert "open" in combined or "sudo" in combined, (
        f"error should be actionable (mention open mode / sudo). err={r.stderr}"
    )


def test_allowlist_mode_fails_clearly_without_sudo(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """allowlist + use_sudo=false: same clear failure as restricted."""
    env = _trusted_config(
        tmp_path,
        '[network]\nmode = "allowlist"\nuse_sudo = false\nallowed_domains = ["github.com"]\n',
    )
    r = _run(coi_binary, workspace_dir, env, ["echo", SENTINEL])
    assert r.returncode != 0, f"allowlist + use_sudo=false must fail. out={r.stdout} err={r.stderr}"
    assert SENTINEL not in r.stdout


def _health_checks(coi_binary, env):
    r = subprocess.run(
        [coi_binary, "health", "--format", "json"],
        capture_output=True,
        text=True,
        # `coi health` launches several ephemeral probe containers
        # (secret_masking, host_credential_isolation, network_restriction,
        # container_connectivity). 30s is too tight on a CI lane that built the
        # coi image cold (heavy CPU/IO contention) — de-flake, not a behavior
        # change.
        timeout=120,
        env=env,
    )
    return json.loads(r.stdout)["checks"]


def _nft_check_status(coi_binary, env):
    return _health_checks(coi_binary, env)["nft"]["status"]


def test_health_open_mode_use_sudo_false_not_failed(coi_binary, tmp_path):
    """`coi health` must not report nft as failed when use_sudo=false + open mode
    (the no-sudoers user gets a clean report). Does not need a container."""
    env = _trusted_config(tmp_path, '[network]\nmode = "open"\nuse_sudo = false\n')
    status = _nft_check_status(coi_binary, env)
    assert status == "ok", f"nft check should be OK for open + use_sudo=false, got {status!r}"


def test_health_open_mode_use_sudo_false_fully_clean(coi_binary, tmp_path):
    """The WHOLE `coi health` report must be sudo-clean with use_sudo=false + open:
    no nft/iptables check should fail or nag the user to configure passwordless
    sudo (the feature's promise — not just the nft check)."""
    env = _trusted_config(tmp_path, '[network]\nmode = "open"\nuse_sudo = false\n')
    checks = _health_checks(coi_binary, env)
    # The sudo-related checks must not be failed, and must not tell the user to
    # add a passwordless-sudo rule they deliberately declined.
    for name in ("nft", "iptables_sudo"):
        c = checks.get(name, {})
        assert c.get("status") != "failed", f"{name} should not be failed: {c}"
        assert (
            "NOPASSWD" not in c.get("message", "")
            and "passwordless sudo" not in c.get("message", "").lower()
        ), f"{name} still nags about passwordless sudo: {c.get('message')!r}"


def test_health_restricted_use_sudo_false_warns_not_fails(coi_binary, tmp_path):
    """restricted + use_sudo=false is a misconfig, reported as warning (not failed)."""
    env = _trusted_config(tmp_path, '[network]\nmode = "restricted"\nuse_sudo = false\n')
    status = _nft_check_status(coi_binary, env)
    assert status == "warning", (
        f"nft check should warn (not fail) for restricted + use_sudo=false, got {status!r}"
    )
