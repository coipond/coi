"""
Test for coi kill - kill nonexistent container.

Tests that:
1. Try to kill a container that doesn't exist
2. Verify it exits non-zero with an error
"""

import subprocess


def test_kill_nonexistent_container(coi_binary, cleanup_containers):
    """
    Test killing a nonexistent container.

    Flow:
    1. Try to kill nonexistent container
    2. Verify it fails with an error message
    """
    fake_container = "coi-nonexistent-kill-test-99999"

    result = subprocess.run(
        [coi_binary, "kill", fake_container],
        capture_output=True,
        text=True,
        timeout=30,
    )

    combined_output = result.stdout + result.stderr

    assert result.returncode != 0, (
        f"Kill of a nonexistent container should fail. Got:\n{combined_output}"
    )
    assert (
        "failed" in combined_output.lower()
        or "warning" in combined_output.lower()
        or "error" in combined_output.lower()
    ), f"Should show error message. Got:\n{combined_output}"
