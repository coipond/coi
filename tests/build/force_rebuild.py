"""
Integration tests for custom image building.

Tests:
- coi build --profile with script
- Force rebuild with --force
"""

import subprocess

import pytest


def test_build_custom_force_rebuild(coi_binary, tmp_path):
    """Test force rebuilding an existing custom image."""
    image_name = "coi-test-custom-force"

    # Skip if base doesn't exist
    result = subprocess.run(
        [coi_binary, "image", "exists", "coi-default"],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("coi-default image not built")

    # Create profile directory with config and build script
    profile_dir = tmp_path / ".coi" / "profiles" / "test-force"
    profile_dir.mkdir(parents=True)

    (profile_dir / "config.toml").write_text(
        f'[container]\nimage = "{image_name}"\n\n[container.build]\nscript = "build.sh"\n'
    )

    build_script = profile_dir / "build.sh"
    build_script.write_text("""#!/bin/bash
set -e
echo "Build v1" > /tmp/version.txt
""")

    # Build first time
    result = subprocess.run(
        [coi_binary, "build", "--profile", "test-force"],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, "First build should succeed"

    # Try to build again without --force (should skip)
    result = subprocess.run(
        [coi_binary, "build", "--profile", "test-force"],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, "Build should succeed but skip"
    assert "already exists" in result.stderr.lower()

    # Update script
    build_script.write_text("""#!/bin/bash
set -e
echo "Build v2" > /tmp/version.txt
""")

    # Build with --force
    result = subprocess.run(
        [coi_binary, "build", "--profile", "test-force", "--force"],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, "Force rebuild should succeed"

    # Cleanup
    subprocess.run([coi_binary, "image", "delete", image_name], check=False)
