"""
Test for coi image list - list Coi images (default behavior).

Tests that:
1. Run coi image list
2. Verify it shows Coi images section
3. Verify output format is correct
"""

import subprocess


def test_list_coi_images(coi_binary, cleanup_containers):
    """
    Test listing Coi images (default behavior).

    Flow:
    1. Run coi image list
    2. Verify output contains Coi Images section
    3. Verify coi image is shown (exists or not built)
    """
    # === Phase 1: Run image list ===

    result = subprocess.run(
        [coi_binary, "image", "list"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, f"Image list should succeed. stderr: {result.stderr}"

    # === Phase 2: Verify output format ===

    combined_output = result.stdout + result.stderr
    assert "Coi Images:" in combined_output or "Available Images:" in combined_output, (
        f"Should show Coi Images section. Got:\n{combined_output}"
    )

    # Should mention the coi image (either built or not)
    assert "coi" in combined_output.lower(), f"Should mention coi image. Got:\n{combined_output}"
