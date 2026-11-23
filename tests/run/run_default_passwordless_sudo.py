"""
Test for coi run - the default profile keeps passwordless sudo.

Tests that:
1. `sudo -n true` succeeds for the code user without a profile
"""

import subprocess


def test_run_default_passwordless_sudo(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that the default profile keeps the code user's passwordless sudo.

    Flow:
    1. Run sudo -n true with coi run (no profile)
    2. Verify it succeeds
    """
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            "sudo -n true && echo SUDO_TRUE_OK || echo SUDO_TRUE_DENIED",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )

    combined_output = result.stdout + result.stderr
    assert result.returncode == 0, f"Run should succeed. Output:\n{combined_output}"
    assert "SUDO_TRUE_OK" in combined_output, (
        f"sudo -n true should work. Output:\n{combined_output}"
    )
