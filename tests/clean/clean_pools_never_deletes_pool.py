"""
Test that `coi clean --pools` never deletes the storage pool itself,
only the Coi containers within it.
"""

import os
import subprocess

import pytest

from support.helpers import (
    create_storage_pool,
    delete_storage_pool,
    is_incus_permission_error,
)


def _pool_exists(name):
    result = subprocess.run(
        ["incus", "storage", "list", "--format=csv"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return False
    return any(line.startswith(name + ",") for line in result.stdout.splitlines())


def test_clean_pools_never_deletes_pool(coi_binary, workspace_dir):
    """After `coi clean --pools --force`, the pool itself remains."""
    pool_name = f"coi-test-keeppool-{os.urandom(4).hex()}"

    ok, err = create_storage_pool(pool_name)
    if not ok:
        if is_incus_permission_error(err):
            pytest.skip(f"No permission to create storage pool {pool_name}: {err}")
        pytest.fail(f"Failed to create temp pool {pool_name}: {err}")

    try:
        # Run clean --pools --force on an empty unreferenced pool.
        result = subprocess.run(
            [
                coi_binary,
                "clean",
                "--pools",
                "--force",
                "--workspace",
                workspace_dir,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=workspace_dir,
        )
        assert result.returncode == 0, f"clean should succeed. stderr: {result.stderr}"

        # Pool itself must still exist
        assert _pool_exists(pool_name), f"Pool {pool_name} should still exist after clean --pools."
    finally:
        delete_storage_pool(pool_name)
