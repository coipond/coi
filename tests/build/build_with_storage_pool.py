"""
Test that `coi build` honours the profile's [container] storage_pool.

A profile with [container.build] and [container] storage_pool should
build the image into the requested pool.
"""

import os
import subprocess

import pytest

from support.helpers import (
    create_storage_pool,
    delete_storage_pool,
    is_incus_permission_error,
)


def test_build_with_storage_pool(coi_binary, tmp_path):
    """coi build should succeed against a profile that selects a custom pool."""
    pool_name = f"coi-test-buildpool-{os.urandom(4).hex()}"

    # Skip if base image isn't available
    result = subprocess.run(
        [coi_binary, "image", "exists", "coi-default"],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("coi-default image not built")

    ok, err = create_storage_pool(pool_name)
    if not ok:
        if is_incus_permission_error(err):
            pytest.skip(f"No permission to create storage pool {pool_name}: {err}")
        pytest.fail(f"Failed to create temp pool {pool_name}: {err}")

    image_name = "coi-test-pool-build"

    try:
        # Cleanup any leftover image
        subprocess.run(
            [coi_binary, "image", "delete", image_name],
            check=False,
            capture_output=True,
        )

        # Profile referencing the temp pool with a build script
        profile_dir = tmp_path / ".coi" / "profiles" / "poolbuild"
        profile_dir.mkdir(parents=True)
        (profile_dir / "config.toml").write_text(
            f"[container]\n"
            f'image = "{image_name}"\n'
            f'storage_pool = "{pool_name}"\n\n'
            f"[container.build]\n"
            f'script = "build.sh"\n'
        )
        (profile_dir / "build.sh").write_text(
            "#!/bin/bash\nset -e\necho 'pool build ok' > /tmp/build_marker.txt\n"
        )

        result = subprocess.run(
            [coi_binary, "build", "--profile", "poolbuild"],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0, (
            f"Build with custom pool should succeed. stderr:\n{result.stderr}"
        )

        # Verify the image now exists
        check = subprocess.run(
            [coi_binary, "image", "exists", image_name],
            capture_output=True,
        )
        assert check.returncode == 0, "Built image should exist"
    finally:
        subprocess.run(
            [coi_binary, "image", "delete", image_name],
            check=False,
            capture_output=True,
        )
        delete_storage_pool(pool_name)
