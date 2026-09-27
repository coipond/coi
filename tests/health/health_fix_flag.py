"""
Tests for `coi health --fix` and its --dry-run companion.

The --fix surface is the documented remediation path (install.sh points users
at it for e.g. the passwordless-nft rule). Integration coverage here is limited
to the flag guards, the --dry-run read-only contract, and runtime --json
routing.

Deliberately NOT tested here: a real (non-dry-run) `coi health --fix`. Applying
remediations mutates shared host state (sudoers drop-in, usermod, sysctl) with
no way to restore it, which would make the suite order-dependent under
pytest-randomly — and on a password-sudo machine with an applicable fix, sudo
would prompt invisibly under pytest's capture and hang until timeout. The
apply path is covered by the Go unit tests in internal/health/remediation_test.go
against an injected registry; the CLI wiring is covered by the dry-run test.

Tests that:
1. --dry-run without --fix is rejected with a clear error
2. --fix with --format json (and the --json alias) is rejected
3. --fix --dry-run prints the remediation plan and changes NOTHING on the host
4. the --json alias routes health to the JSON formatter at runtime

Notes for CI: these run against whatever state the lane has. We deliberately do
NOT assert whether any remediation is applicable (that is environment-dependent)
— only the invariants: guards fire, dry-run mutates nothing, headers print, and
exit codes stay within the documented set.
"""

import json
import subprocess
from pathlib import Path

import pytest


def _run_health(coi_binary, *args, timeout=300):
    return subprocess.run(
        [coi_binary, "health", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _sudo_stat(path):
    """Observe a root-only path via `sudo -n stat`: size|mtime|mode, None if
    absent, or the sentinel "unobservable" when even sudo can't look.

    /etc/sudoers.d is 0750 root:root on GitHub runners (and RHEL), so the
    drop-in can't be stat()ed — or even seen — by the test user directly.
    Passwordless sudo is present on every CI lane, so the metadata is observed
    through `sudo -n stat` (-n fails fast instead of prompting on password-sudo
    hosts). %y carries nanosecond mtime, so a same-second rewrite still shows.
    The "unobservable" sentinel is returned consistently for both snapshots on
    hosts without passwordless sudo, keeping the comparison valid — the
    contract simply isn't assertable where we cannot look.
    """
    result = subprocess.run(
        ["sudo", "-n", "stat", "-c", "%s|%y|%a", str(path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    if "No such file" in result.stderr:
        return None
    return "unobservable"


def _snapshot_fix_targets():
    """Capture the host state the --fix remediations could durably write.

    The safe-remediation registry currently has three fixes; two of their
    targets are snapshotted here:
      - /etc/sudoers.d/coi-nft (nft rule) — via sudo -n stat metadata
      - incus-admin membership in /etc/group (usermod) — world-readable content

    net.ipv4.ip_forward (the sysctl fix's target) is deliberately NOT
    snapshotted: the health run between the two snapshots launches probe
    containers, and Incus bringing up bridge networking for a probe can
    legitimately set ip_forward=1 — the test would blame --dry-run for a
    change the (read-only) checks caused.

    internal/health/remediation_test.go pins the registry size and points
    here, so adding a fourth remediation fails loudly until this snapshot is
    extended.
    """
    snapshot = {
        "coi_nft": _sudo_stat(Path("/etc/sudoers.d/coi-nft")),
    }
    group_lines = [
        line
        for line in Path("/etc/group").read_text().splitlines()
        if line.startswith("incus-admin:")
    ]
    snapshot["incus_admin_group"] = group_lines
    return snapshot


def test_dry_run_requires_fix(coi_binary):
    """--dry-run only makes sense with --fix; alone it must be rejected."""
    result = _run_health(coi_binary, "--dry-run", timeout=60)
    assert result.returncode != 0, "bare --dry-run should be rejected"
    combined = result.stdout + result.stderr
    assert "--dry-run only applies together with --fix" in combined, combined


@pytest.mark.parametrize(
    "argv",
    [("--fix", "--format", "json"), ("--fix", "--json")],
    ids=["format-json", "json-alias"],
)
def test_fix_rejects_json_output(coi_binary, argv):
    """--fix is text-mode only; --format json and its --json alias are both
    rejected before any check runs."""
    result = _run_health(coi_binary, *argv, timeout=60)
    assert result.returncode != 0, f"--fix with {argv} should be rejected"
    combined = result.stdout + result.stderr
    assert "not supported with --format json" in combined, combined


def test_fix_dry_run_prints_plan_and_changes_nothing(coi_binary):
    """
    The core --dry-run contract: show the plan, mutate nothing.

    Flow:
    1. Snapshot the durable targets the remediation registry can write
    2. Run coi health --fix --dry-run
    3. Verify the plan header printed, followed by the normal health table
    4. Verify the exit code still follows the health contract (0/1/2)
    5. Verify the snapshot is unchanged
    """
    before = _snapshot_fix_targets()

    result = _run_health(coi_binary, "--fix", "--dry-run")

    assert "Remediation plan (--dry-run" in result.stdout, result.stdout
    assert "Code on Incus Health Check" in result.stdout, (
        f"dry-run should still print the health table:\n{result.stdout}"
    )
    assert result.returncode in (0, 1, 2), (
        f"--fix --dry-run exit code must follow the health contract, got {result.returncode}:"
        f"\n{result.stdout}\n{result.stderr}"
    )

    after = _snapshot_fix_targets()
    assert after == before, f"--dry-run must not modify the host.\nbefore: {before}\nafter: {after}"


def test_json_alias_routes_to_json_output(coi_binary):
    """
    `coi health --json` must route to the JSON formatter at runtime.

    Help-level alias recognition is covered by tests/cli/test_json_alias.py and
    the full JSON document contract by health_json_output.py; this pins the one
    remaining piece — that the alias actually produces the JSON document when
    executed (not just that the flag parses).
    """
    result = _run_health(coi_binary, "--json")

    data = json.loads(result.stdout)
    assert isinstance(data, dict) and "status" in data, (
        f"--json should emit the health JSON document, got: {result.stdout[:200]}"
    )
