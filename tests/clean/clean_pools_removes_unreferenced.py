"""
Test that `coi clean --pools --force` removes containers in unreferenced pools.

Creates a temp pool, creates a coi-prefixed container in it, and verifies
that `coi clean --pools --force` removes the container while leaving the
pool itself intact.
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


def _delete_container(name):
    subprocess.run(
        ["incus", "delete", name, "--force"],
        capture_output=True,
        timeout=30,
    )


def test_clean_pools_removes_unreferenced(coi_binary, workspace_dir):
    """clean --pools --force removes coi containers in unreferenced pools."""
    pool_name = f"coi-test-removepool-{os.urandom(4).hex()}"
    container_name = "coi-test-orphan-container-rm"

    ok, err = create_storage_pool(pool_name)
    if not ok:
        if is_incus_permission_error(err):
            pytest.skip(f"No permission to create storage pool {pool_name}: {err}")
        pytest.fail(f"Failed to create temp pool {pool_name}: {err}")

    try:
        # Launch a coi-prefixed container in the temp pool. Use a minimal
        # ubuntu image so we don't depend on a coi image being preloaded
        # in the temp pool.
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
            # Run clean --pools --force from a clean workspace (no profiles
            # reference the temp pool, so it counts as unreferenced).
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
                timeout=120,
                cwd=workspace_dir,
            )
            assert result.returncode == 0, (
                f"clean --pools --force should succeed. stderr: {result.stderr}"
            )

            # The container should be gone
            status = incus_status(container_name)
            assert status == "", (
                f"Container {container_name} should be deleted. Got status {status!r}"
            )

            # The pool itself should NOT be deleted
            assert _pool_exists(pool_name), f"Pool {pool_name} should still exist after cleanup."
        finally:
            _delete_container(container_name)
    finally:
        delete_storage_pool(pool_name)
