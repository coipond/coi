"""
Integration test for #838: when the host UID sits inside a multi-ID subordinate
range in /etc/subuid (as with Google Cloud OS Login UIDs inside root's delegation
block), Incus can't idmap the workspace. The secret-masking / host-credential
probes must then SKIP with a named WARNING instead of the cryptic forkmount
[FAIL] the bug reported.

This drives the REAL binary: it temporarily adds a count>1 subuid range covering
the current test user's UID, runs `coi health --json`, and asserts the two idmap
probes report a `warning` naming the /etc/subuid cause — then restores
/etc/subuid exactly. The probe skip fires before any container launch, so this
needs neither the coi image nor a mappable UID.
"""

import json
import os
import subprocess

import pytest


def _sudo_ok():
    return subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True).returncode == 0


def _read_subuid():
    """Return the current /etc/subuid bytes, or None if it doesn't exist."""
    r = subprocess.run(["sudo", "-n", "cat", "/etc/subuid"], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def _write_subuid(content: bytes):
    subprocess.run(
        ["sudo", "-n", "tee", "/etc/subuid"], input=content, capture_output=True, check=True
    )


def _restore_subuid(original):
    if original is None:
        subprocess.run(["sudo", "-n", "rm", "-f", "/etc/subuid"], capture_output=True)
    else:
        _write_subuid(original)


def test_idmap_probes_skip_when_uid_in_subuid_range(coi_binary):
    if not _sudo_ok():
        pytest.skip("passwordless sudo required to manipulate /etc/subuid")

    uid = os.getuid()
    original = _read_subuid()
    base = original if original is not None else b""
    # Guarantee a separator: if /etc/subuid has no trailing newline, a bare
    # concatenation would merge the injected line into the last existing one and
    # corrupt both (neither would parse), so the probe wouldn't skip.
    if base and not base.endswith(b"\n"):
        base += b"\n"
    # A dedicated multi-ID range covering the current UID → reproduces the #838
    # "host UID inside a subordinate range" condition (count>1 is what breaks).
    injected = base + f"coitest838:{uid}:2\n".encode()

    try:
        _write_subuid(injected)
        result = subprocess.run(
            [coi_binary, "health", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        _restore_subuid(original)

    assert result.returncode in (0, 1, 2), (
        f"coi health did not run (exit {result.returncode}).\n{result.stdout}\n{result.stderr}"
    )
    checks = json.loads(result.stdout)["checks"]

    for name in ("secret_masking", "host_credential_isolation"):
        assert name in checks, f"missing {name} check: {list(checks)}"
        c = checks[name]
        assert c["status"] == "warning", (
            f"{name} should skip to WARNING when the UID can't be idmapped, "
            f"got {c['status']}: {c['message']}"
        )
        msg = c["message"]
        assert f"host UID {uid}" in msg and "/etc/subuid range" in msg, (
            f"{name} message should name the subuid cause, got: {msg}"
        )
        assert "not a masking failure" in msg, (
            f"{name} message should clarify it isn't a real failure, got: {msg}"
        )
