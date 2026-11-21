"""
Test that profiles can be loaded from self-contained directories.

Tests that:
1. Profile loaded from .coi/profiles/NAME/config.toml is applied
2. Profile environment from directory config is injected
"""

import subprocess
from pathlib import Path


def test_profile_directory_environment(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that a profile directory's environment vars are applied.

    Flow:
    1. Create .coi/profiles/myprof/config.toml with environment
    2. Run coi run --profile myprof -- sh -c 'echo $MY_DIR_VAR'
    3. Verify env var is set
    """
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "myprof"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        """
[environment]
MY_DIR_VAR = "from-directory-profile"
"""
    )

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--profile",
            "myprof",
            "--",
            "sh",
            "-c",
            "echo VAL=$MY_DIR_VAR",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"
    combined = result.stdout + result.stderr
    assert "VAL=from-directory-profile" in combined, (
        f"Directory profile env should be applied. Got:\n{combined}"
    )


def test_profile_directory_image(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that a profile directory can set the image.

    Flow:
    1. Create .coi/profiles/imgprof/config.toml with [container] image = "coi-default"
    2. Run coi run --profile imgprof -- echo ok
    3. Verify it runs successfully (image resolved)
    """
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "imgprof"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text('[container]\nimage = "coi-default"\n')

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--profile",
            "imgprof",
            "echo",
            "profile-dir-ok",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"
    combined = result.stdout + result.stderr
    assert "profile-dir-ok" in combined, f"Expected output from container. Got:\n{combined}"


def test_profile_directory_not_found(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that using a non-existent profile name fails gracefully.

    Flow:
    1. No profiles defined
    2. Run coi run --profile nonexistent -- echo test
    3. Verify it fails with error
    """
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--profile",
            "nonexistent",
            "echo",
            "test",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )

    assert result.returncode != 0, "Should fail with non-existent profile"
    combined = result.stdout + result.stderr
    assert "not found" in combined.lower(), (
        f"Error should mention profile not found. Got:\n{combined}"
    )
