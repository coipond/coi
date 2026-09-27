"""
Tests for `coi health --fix` and its --dry-run companion.

The --fix surface is the documented remediation path (install.sh points users
at it for e.g. the passwordless-nft rule), but until now had no integration
coverage: the flag guards, the dry-run read-only contract, and the report
headers were only exercised by Go unit tests against a fake registry.

Tests that:
1. --dry-run without --fix is rejected with a clear error
2. --fix with --format json (and the --json alias) is rejected
3. --fix --dry-run prints the remediation plan and changes NOTHING on the host
4. --fix prints the "Applying remediations" report and a normal health table,
   with an exit code that still follows the healthy/degraded/unhealthy contract
5. the --json alias produces the same JSON document shape as --format json

Notes for CI: these run against whatever state the lane has. We deliberately do
NOT assert whether any remediation is applicable (that is environment-dependent)
— only the invariants: guards fire, dry-run mutates nothing, headers print, and
exit codes stay within the documented set.
"""

import json
import subprocess
from pathlib import Path


def _run_health(coi_binary, *args, timeout=300):
    return subprocess.run(
        [coi_binary, "health", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _snapshot_fix_targets():
    """Capture the host state every registered remediation could touch.

    The safe-remediation registry currently writes exactly three things:
    /etc/sudoers.d/coi-nft (nft rule), net.ipv4.ip_forward (sysctl), and
    incus-admin membership in /etc/group (usermod). All are world-readable, so
    the read-only contract of --dry-run can be asserted without root.
    """
    nft = Path("/etc/sudoers.d/coi-nft")
    snapshot = {
        "coi_nft": nft.read_text() if nft.exists() else None,
    }
    ip_forward = Path("/proc/sys/net/ipv4/ip_forward")
    snapshot["ip_forward"] = ip_forward.read_text() if ip_forward.exists() else None
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


def test_fix_rejects_json_format(coi_binary):
    """--fix is text-mode only; --format json must be rejected before any work."""
    result = _run_health(coi_binary, "--fix", "--format", "json", timeout=60)
    assert result.returncode != 0, "--fix with --format json should be rejected"
    combined = result.stdout + result.stderr
    assert "not supported with --format json" in combined, combined


def test_fix_rejects_json_alias(coi_binary):
    """The --json shorthand resolves to --format json, so it hits the same guard."""
    result = _run_health(coi_binary, "--fix", "--json", timeout=60)
    assert result.returncode != 0, "--fix with --json alias should be rejected"
    combined = result.stdout + result.stderr
    assert "not supported with --format json" in combined, combined


def test_fix_dry_run_prints_plan_and_changes_nothing(coi_binary):
    """
    The core --dry-run contract: show the plan, mutate nothing.

    Flow:
    1. Snapshot everything the remediation registry can write
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


def test_fix_reports_and_prints_health_table(coi_binary):
    """
    A real --fix run prints the remediation report above the health table.

    We do not assert whether anything was applied — on a properly configured
    lane there is usually nothing to fix — only that the report and table
    render and the exit code stays within the documented set.
    """
    result = _run_health(coi_binary, "--fix")

    assert "Applying remediations:" in result.stdout, result.stdout
    assert "Code on Incus Health Check" in result.stdout, result.stdout
    assert "STATUS:" in result.stdout, result.stdout
    assert result.returncode in (0, 1, 2), (
        f"--fix exit code must follow the health contract, got {result.returncode}:"
        f"\n{result.stdout}\n{result.stderr}"
    )


def test_json_alias_matches_format_json_shape(coi_binary):
    """
    `coi health --json` (the shorthand) must produce the same document shape as
    `--format json`: top-level status/checks/summary, with a valid status value.
    """
    result = _run_health(coi_binary, "--json")

    data = json.loads(result.stdout)
    for key in ("status", "checks", "summary"):
        assert key in data, f"missing top-level key {key!r}: {list(data)}"
    assert data["status"] in ("healthy", "degraded", "unhealthy"), data["status"]
    assert isinstance(data["checks"], dict) and data["checks"], "checks should be non-empty"

    expected_exit = {"healthy": 0, "degraded": 1, "unhealthy": 2}[data["status"]]
    assert result.returncode == expected_exit, (
        f"exit code {result.returncode} doesn't match status {data['status']!r}"
    )
