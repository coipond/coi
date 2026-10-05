"""
Integration test for #838: when the host UID sits inside a multi-ID subordinate
range in /etc/subuid (as with Google Cloud OS Login UIDs inside root's delegation
block), Incus can't idmap the workspace. The secret-masking / host-credential
probes must then SKIP with a named WARNING instead of the cryptic forkmount
[FAIL] the bug reported.

This drives the REAL binary: it temporarily rewrites /etc/subuid so a ROOT-owned
count>1 range covers the current test user's UID with no dedicated
`root:<uid>:1` line (the #838 condition — Incus allocates idmaps from root's
delegations, and a dedicated size-1 line is the fix coi prints, which clears
it), runs `coi health --json`, and asserts the two idmap probes report a
`warning` naming the /etc/subuid cause — then restores /etc/subuid exactly.
The probe skip fires before any container launch, so this needs neither the
coi image nor a mappable UID.
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
    # Drop any dedicated root:<uid>:1 delegation (CI adds root:1001:1 for
    # raw.idmap): it is the fix for #838, so while present the UID counts as
    # mappable and the probes rightly run instead of skipping.
    dedicated = {f"root:{uid}:1".encode(), f"0:{uid}:1".encode()}
    base = b"".join(
        line for line in base.splitlines(keepends=True) if line.strip() not in dedicated
    )
    # A root-owned multi-ID range covering the current UID → reproduces the #838
    # "host UID inside root's subordinate range" condition (count>1 is what
    # breaks; another user's range is irrelevant to Incus).
    injected = base + f"root:{uid}:2\n".encode()

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


def _read_file(path):
    """Return the bytes of a root-owned file, or None if it doesn't exist."""
    r = subprocess.run(["sudo", "-n", "cat", path], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def _write_file(path, content: bytes):
    subprocess.run(["sudo", "-n", "tee", path], input=content, capture_output=True, check=True)


def _restore_file(path, original):
    if original is None:
        subprocess.run(["sudo", "-n", "rm", "-f", path], capture_output=True)
    else:
        _write_file(path, original)


def _with_newline(b):
    return b + b"\n" if b and not b.endswith(b"\n") else b


def _strip_dedicated(content, uid):
    dedicated = {f"root:{uid}:1".encode(), f"0:{uid}:1".encode()}
    return b"".join(
        line for line in content.splitlines(keepends=True) if line.strip() not in dedicated
    )


def _health_probe_messages(coi_binary, subuid, subgid):
    """Temporarily install the given /etc/subuid and /etc/subgid contents, run
    `coi health --json`, restore both files exactly, and return the two idmap
    probe checks."""
    orig_uid, orig_gid = _read_file("/etc/subuid"), _read_file("/etc/subgid")
    try:
        _write_file("/etc/subuid", subuid)
        _write_file("/etc/subgid", subgid)
        result = subprocess.run(
            [coi_binary, "health", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        _restore_file("/etc/subuid", orig_uid)
        _restore_file("/etc/subgid", orig_gid)
    assert result.returncode in (0, 1, 2), (
        f"coi health did not run (exit {result.returncode}).\n{result.stdout}\n{result.stderr}"
    )
    checks = json.loads(result.stdout)["checks"]
    return {name: checks[name] for name in ("secret_masking", "host_credential_isolation")}


def _incusd_running():
    return subprocess.run(["pgrep", "-x", "incusd"], capture_output=True).returncode == 0


def test_dedicated_line_in_subuid_only_names_missing_subgid(coi_binary):
    """coi's printed fix adds root:<uid>:1 to BOTH /etc/subuid and /etc/subgid.
    With it only in /etc/subuid, the probes keep skipping and say what's missing,
    rather than clearing and failing with a cryptic forkmount error."""
    if not _sudo_ok():
        pytest.skip("passwordless sudo required to manipulate /etc/subuid and /etc/subgid")
    uid = os.getuid()
    big = f"root:{uid}:2\n".encode()
    dedicated = f"root:{uid}:1\n".encode()
    base_uid = _strip_dedicated(_with_newline(_read_file("/etc/subuid") or b""), uid)
    base_gid = _strip_dedicated(_with_newline(_read_file("/etc/subgid") or b""), uid)

    checks = _health_probe_messages(coi_binary, base_uid + big + dedicated, base_gid + big)
    for name, c in checks.items():
        assert c["status"] == "warning", f"{name} should still skip, got {c['status']}: {c}"
        assert "missing from /etc/subgid" in c["message"], (
            f"{name} should name the missing /etc/subgid line, got: {c['message']}"
        )


def test_dedicated_lines_newer_than_incusd_ask_for_restart(coi_binary):
    """Incus reads the subordinate-ID files at start. Writing the dedicated
    lines now (after the running incusd started) must keep the probes skipping
    with a "restart Incus" hint. This exercises locating the real daemon via
    /proc on the host, not a container monitor."""
    if not _sudo_ok():
        pytest.skip("passwordless sudo required to manipulate /etc/subuid and /etc/subgid")
    if not _incusd_running():
        pytest.skip("no incusd process visible on this host")
    uid = os.getuid()
    big = f"root:{uid}:2\n".encode()
    dedicated = f"root:{uid}:1\n".encode()
    base_uid = _strip_dedicated(_with_newline(_read_file("/etc/subuid") or b""), uid)
    base_gid = _strip_dedicated(_with_newline(_read_file("/etc/subgid") or b""), uid)

    checks = _health_probe_messages(
        coi_binary, base_uid + big + dedicated, base_gid + big + dedicated
    )
    for name, c in checks.items():
        assert c["status"] == "warning", f"{name} should still skip, got {c['status']}: {c}"
        assert "hasn't been restarted" in c["message"], (
            f"{name} should ask for an Incus restart, got: {c['message']}"
        )
