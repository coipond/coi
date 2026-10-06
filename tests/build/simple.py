"""
Integration tests for custom image building.

Tests:
- coi build --profile with script
- Custom image with base specified
- Custom image with privileged base
"""

import subprocess
import time

import pytest


def test_build_custom_simple(coi_binary, tmp_path):
    """Test building a custom image with a simple script via profile."""
    image_name = "coi-test-custom-simple"

    # Build custom image (needs the coi-default image)
    result = subprocess.run(
        [coi_binary, "image", "exists", "coi-default"],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("coi-default image not built")

    # Cleanup any existing image from previous run
    subprocess.run([coi_binary, "image", "delete", image_name], check=False, capture_output=True)

    # Create profile directory with config and build script
    profile_dir = tmp_path / ".coi" / "profiles" / "test-simple"
    profile_dir.mkdir(parents=True)

    (profile_dir / "config.toml").write_text(
        f'[container]\nimage = "{image_name}"\n\n[container.build]\nscript = "build.sh"\n'
    )

    (profile_dir / "build.sh").write_text("""#!/bin/bash
set -e
apt-get update
apt-get install -y curl
echo "Custom build completed" > /tmp/build_marker.txt
""")

    # Build custom image
    result = subprocess.run(
        [coi_binary, "build", "--profile", "test-simple"],
        capture_output=True,
        text=True,
        timeout=300,  # 5 minutes
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, f"Build failed: {result.stderr}"

    # Verify image exists
    result = subprocess.run(
        [coi_binary, "image", "exists", image_name],
        capture_output=True,
    )
    assert result.returncode == 0, "Custom image should exist"

    # Launch container from custom image to verify
    container_name = "coi-test-custom-verify"
    result = subprocess.run(
        [coi_binary, "container", "launch", image_name, container_name],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Launch from custom image failed: {result.stderr}"
    time.sleep(3)

    # Verify curl is installed (from our script)
    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "which", "curl"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, "curl should be installed"

    # Cleanup
    subprocess.run([coi_binary, "container", "delete", container_name, "--force"], check=False)
    subprocess.run([coi_binary, "image", "delete", image_name], check=False)
