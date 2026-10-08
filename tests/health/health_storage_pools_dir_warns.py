"""
A pool on the `dir` driver is flagged by the storage pool health check.

A `dir` pool has no unpacked image volume to clone from, so every launch
re-unpacks the whole image; `coi health` must name the driver and warn,
whether or not the pool's usage could be read (#659). Its driver is known, so
it is never reported as "missing" — on runners where the usage query fails it
is "usage unavailable" instead. The per-driver logic is unit-tested in
internal/health/checks_test.go; this runs it end to end against a real pool.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from support.helpers import (
    create_storage_pool,
    delete_storage_pool,
    is_incus_permission_error,
)


def test_health_storage_pools_dir_driver_warns(coi_binary, workspace_dir):
    pool_name = f"coi-test-dirpool-{os.urandom(4).hex()}"

    ok, err = create_storage_pool(pool_name, driver="dir")
    if not ok:
        if is_incus_permission_error(err):
            pytest.skip(f"No permission to create storage pool {pool_name}: {err}")
        pytest.fail(f"Failed to create temp pool {pool_name}: {err}")

    try:
        profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "dirpool"
        profile_dir.mkdir(parents=True)
        (profile_dir / "config.toml").write_text(
            f'[container]\nimage = "coi-default"\nstorage_pool = "{pool_name}"\n'
        )

        result = subprocess.run(
            [coi_binary, "health", "--format", "json", "--workspace", workspace_dir],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=workspace_dir,
        )
        # A warning or failed check makes the aggregate exit non-zero; that is
        # expected here.
        assert result.returncode in (0, 1, 2), (
            f"health exited {result.returncode}.\n--- report ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )

        check = json.loads(result.stdout)["checks"]["incus_storage_pools"]
        entry = check.get("details", {}).get(pool_name)
        assert entry is not None, (
            f"{pool_name} should be listed. Got: {list(check.get('details', {}))}"
        )
        assert entry.get("driver") == "dir", (
            f"the pool's driver should be detected as dir. Got: {entry}"
        )
        # Healthy usage -> warning; failed only when usage could not be read or
        # the runner's disk is nearly full. Never ok for a dir pool.
        assert entry.get("status") in ("warning", "failed"), (
            f"a dir pool must not be ok. Got: {entry}"
        )
        assert check["status"] in ("warning", "failed"), (
            f"the check must not be ok with a dir pool. Got: {check}"
        )

        message = check.get("message", "")
        assert (
            f"{pool_name} (dir): 'dir' storage driver re-unpacks the image on every launch"
            in message
        ), f"expected the dir-driver warning for {pool_name}. Message: {message}"
        assert f"{pool_name}: missing" not in message, (
            f"a pool whose driver is known must never be reported missing. Message: {message}"
        )
    finally:
        delete_storage_pool(pool_name)
