"""
Integration tests for [container.build] compression (config-driven; the former
--compression build flag was removed — config-shaped settings live in
config/profiles, not flags).

Currently covered:
- the default-image path is covered by unit tests (see the note below)
- coi build --profile <name> with compression in the profile's build section
- the removed --compression flag fails with the config migration hint
"""

import subprocess
import time

# The default-image variant (`coi build --force` with compression = "none")
# used to live here. It rebuilt the whole coi image from the network — its
# apt step alone took up to 24 minutes against a slow mirror, or failed with
# mirror 502s — so it was flaky against its 600s timeout, and it swapped the
# shared coi-default image mid-run. Its coverage is now deterministic:
#   - internal/cli TestCoiImageBuildOptions: the profile's compression reaches
#     the default-image build options (`coi build` and `coi build --all`);
#   - internal/image TestCreateImage_PassesCompression: build options become
#     `incus publish --compression none`;
#   - test_build_custom_with_compression_none below: the same publish path end
#     to end, on top of the existing image (no package downloads).


def test_build_custom_with_compression_none(coi_binary, tmp_path):
    """Test building a custom image with --compression none flag via profile."""
    image_name = "coi-test-compression"

    # Build custom image (skip if coi doesn't exist)
    result = subprocess.run(
        [coi_binary, "image", "exists", "coi-default"],
        capture_output=True,
    )
    if result.returncode != 0:
        # Skip test if base image doesn't exist
        return

    # Cleanup any existing image from previous run
    subprocess.run([coi_binary, "image", "delete", image_name], check=False, capture_output=True)

    # Create profile directory with config and build script
    profile_dir = tmp_path / ".coi" / "profiles" / "test-compression"
    profile_dir.mkdir(parents=True)

    (profile_dir / "config.toml").write_text(
        f'[container]\nimage = "{image_name}"\n\n'
        '[container.build]\nscript = "build.sh"\ncompression = "none"\n'
    )

    (profile_dir / "build.sh").write_text("""#!/bin/bash
set -e
apt-get update
apt-get install -y curl
echo "Custom build completed" > /tmp/build_marker.txt
""")

    # Build custom image; compression comes from the profile's build section
    result = subprocess.run(
        [coi_binary, "build", "--profile", "test-compression"],
        capture_output=True,
        text=True,
        timeout=300,
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
    container_name = "coi-test-compression-verify"
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


def test_build_compression_flag_removed(coi_binary):
    """The removed --compression flag fails with the config migration hint."""
    result = subprocess.run(
        [coi_binary, "build", "--compression", "none"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0, "removed --compression flag must fail"
    assert "flag was removed" in result.stderr, f"want migration hint, got:\n{result.stderr}"
    assert "[container.build] compression" in result.stderr, (
        f"hint must point at the build config key, got:\n{result.stderr}"
    )
