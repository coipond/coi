"""
Test that `coi clean --pools --dry-run` lists targets but deletes nothing.
"""

import os
import subprocess

import pytest

from support.helpers import (
    create_storage_pool,
    delete_storage_pool,
    incus_status,
    is_incus_permission_error,
)


def _delete_container(name):
    subprocess.run(
        ["incus", "delete", name, "--force"],
        capture_output=True,
        timeout=30,
    )


def test_clean_pools_dry_run(coi_binary, workspace_dir):
    """--dry-run lists what would be deleted but deletes nothing."""
    pool_name = f"coi-test-dryrunpool-{os.urandom(4).hex()}"
    container_name = "coi-test-dryrun-container"

    ok, err = create_storage_pool(pool_name)
    if not ok:
        if is_incus_permission_error(err):
            pytest.skip(f"No permission to create storage pool {pool_name}: {err}")
        pytest.fail(f"Failed to create temp pool {pool_name}: {err}")

    try:
        result = subprocess.run(
            [
                "incus",
                "init",
                "images:ubuntu/22.04",
                container_name,
                "-s",
                pool_name,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.skip(f"Cannot init container in temp pool: {result.stderr}")

        try:
            result = subprocess.run(
                [
                    coi_binary,
                    "clean",
                    "--pools",
                    "--dry-run",
                    "--workspace",
                    workspace_dir,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=workspace_dir,
            )
            assert result.returncode == 0, f"dry-run should succeed. stderr: {result.stderr}"

            combined = result.stdout + result.stderr
            assert container_name in combined, (
                f"Dry-run should list the container. Got:\n{combined}"
            )

            # Container should still exist
            assert incus_status(container_name) != "", "Container should still exist after dry-run."
        finally:
            _delete_container(container_name)
    finally:
        delete_storage_pool(pool_name)
