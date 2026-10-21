"""
Integration test for coi build --all when one profile fails to build.

Tests that:
1. A failing profile does not stop the other profiles from building
2. The build summary counts the built and failed profiles
3. The command exits non-zero and names the failed profile
"""

import re
import subprocess

import pytest


def test_build_all_continues_past_failing_profile(coi_binary, tmp_path):
    """
    Test that 'coi build --all' keeps going after one profile fails.

    Flow:
    1. Create profile alpha whose build commands exit 1 (sorts first)
    2. Create profile beta whose build commands succeed
    3. Run 'coi build --all'
    4. Verify beta's image exists and alpha's does not
    5. Verify the build summary (Built: 1, Failed: 1) comes before the error
    6. Verify a non-zero exit with "1 build(s) failed:" and "  profile 'alpha': "
    7. Cleanup
    """
    image_alpha = "coi-test-all-fail-alpha"
    image_beta = "coi-test-all-fail-beta"

    result = subprocess.run(
        [coi_binary, "image", "exists", "coi-default"],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("coi base image not found")

    for img in (image_alpha, image_beta):
        subprocess.run(
            [coi_binary, "image", "delete", img],
            check=False,
            capture_output=True,
        )

    # Profile alpha — its build commands fail
    profile_alpha = tmp_path / ".coi" / "profiles" / "alpha"
    profile_alpha.mkdir(parents=True)
    (profile_alpha / "config.toml").write_text(
        f'[container]\nimage = "{image_alpha}"\n\n'
        '[container.build]\nbase = "coi-default"\n'
        'commands = ["exit 1"]\n'
    )

    # Profile beta — builds after alpha and must still succeed
    profile_beta = tmp_path / ".coi" / "profiles" / "beta"
    profile_beta.mkdir(parents=True)
    (profile_beta / "config.toml").write_text(
        f'[container]\nimage = "{image_beta}"\n\n'
        '[container.build]\nbase = "coi-default"\n'
        'commands = ["echo beta > /tmp/marker.txt"]\n'
    )

    try:
        # === Phase 1: build everything ===
        result = subprocess.run(
            [coi_binary, "build", "--all"],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(tmp_path),
        )
        stderr = result.stderr

        assert result.returncode != 0, (
            f"coi build --all should fail when a profile fails. stderr: {stderr}"
        )

        # === Phase 2: beta was built despite alpha failing ===
        check = subprocess.run(
            [coi_binary, "image", "exists", image_beta],
            capture_output=True,
        )
        assert check.returncode == 0, f"Image '{image_beta}' should exist. stderr: {stderr}"
        check = subprocess.run(
            [coi_binary, "image", "exists", image_alpha],
            capture_output=True,
        )
        assert check.returncode != 0, f"Image '{image_alpha}' should not exist. stderr: {stderr}"
        assert f"[beta] Image '{image_beta}' built successfully." in stderr, (
            f"beta should be reported as built. stderr: {stderr}"
        )

        # === Phase 3: summary, then the error naming the failed profile ===
        summary = stderr.find("--- Build summary ---")
        assert summary != -1, f"Output should contain the build summary. stderr: {stderr}"
        assert re.search(r"^  Built:\s+1$", stderr[summary:], re.MULTILINE), (
            f"Summary should count 1 built profile. stderr: {stderr}"
        )
        assert re.search(r"^  Failed:\s+1$", stderr[summary:], re.MULTILINE), (
            f"Summary should count 1 failed profile. stderr: {stderr}"
        )

        failed = stderr.find("1 build(s) failed:")
        assert failed > summary, f"The error should follow the summary. stderr: {stderr}"
        assert "\n  profile 'alpha': " in stderr[failed:], (
            f"The error should name the failed profile. stderr: {stderr}"
        )
        assert "profile 'beta'" not in stderr[failed:], (
            f"The error should not name the built profile. stderr: {stderr}"
        )
    finally:
        # === Cleanup ===
        for img in (image_alpha, image_beta):
            subprocess.run(
                [coi_binary, "image", "delete", img],
                check=False,
                capture_output=True,
            )
