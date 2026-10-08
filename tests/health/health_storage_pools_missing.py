"""
Test that profile referencing a non-existent pool flags it as missing/failed
in the storage pool health check.
"""

import json
import subprocess
from pathlib import Path


def test_health_storage_pools_missing(coi_binary, workspace_dir):
    """Profile pointing at a non-existent pool causes a failed entry."""
    missing_pool = "coi-test-missing-pool-xyz"
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "missingpool"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        f'[container]\nimage = "coi-default"\nstorage_pool = "{missing_pool}"\n'
    )

    result = subprocess.run(
        [coi_binary, "health", "--format", "json", "--workspace", workspace_dir],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )
    # Health may exit non-zero when a check fails — that's the expected outcome.
    assert result.stdout, f"Should produce JSON output. stderr: {result.stderr}"

    data = json.loads(result.stdout)
    details = data["checks"]["incus_storage_pools"]["details"]

    assert missing_pool in details, (
        f"Missing pool {missing_pool} should appear in details. Got: {list(details.keys())}"
    )
    entry = details[missing_pool]
    assert entry.get("status") == "failed", (
        f"Missing pool entry should have status=failed. Got: {entry}"
    )
    # An unresolvable pool (no driver) is reported as "missing" — not as
    # "usage unavailable", which is reserved for a pool that exists (driver
    # known) but whose usage query failed.
    message = data["checks"]["incus_storage_pools"]["message"]
    assert f"{missing_pool}: missing" in message, (
        f"an unresolvable pool should be reported as missing. Message: {message}"
    )
    assert (
        f"{missing_pool}: usage unavailable" not in message and f"{missing_pool} (" not in message
    ), f"an unresolvable pool has no driver and is not 'usage unavailable'. Message: {message}"
