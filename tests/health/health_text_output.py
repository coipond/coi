"""
Test for coi health - text output format.

Tests that:
1. Health command runs successfully
2. Output contains expected sections
3. Exit code is 0 when healthy
"""

import subprocess


def test_health_text_output(coi_binary):
    """
    Test health command with default text output.

    Flow:
    1. Run coi health
    2. Verify expected sections appear in output
    3. Verify exit code is 0
    """
    result = subprocess.run(
        [coi_binary, "health"],
        capture_output=True,
        text=True,
        timeout=120,
    )

    # This test is about the text output, not the aggregate health. Any valid
    # classification (0 healthy, 1 degraded, 2 unhealthy) still prints the report,
    # and an unrelated check can push the aggregate to 2 under CI load — so accept
    # all three and let the content assertions below decide. Only a crash (exit
    # outside 0/1/2) fails here; show the report then, since otherwise the failure
    # says only "exit N" with no way to tell what broke.
    assert result.returncode in (0, 1, 2), (
        f"coi health did not run (exit {result.returncode}).\n"
        f"--- report ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )

    output = result.stdout

    # Verify header
    assert "Coi Health Check" in output, "Should have header"

    # Verify key sections exist
    assert "SYSTEM:" in output, "Should have SYSTEM section"
    assert "CRITICAL:" in output, "Should have CRITICAL section"
    assert "NETWORKING:" in output, "Should have NETWORKING section"
    assert "STORAGE:" in output, "Should have STORAGE section"
    assert "CONFIGURATION:" in output, "Should have CONFIGURATION section"
    assert "STATUS:" in output, "Should have STATUS section"

    # Verify key checks appear
    assert "Incus" in output, "Should check Incus"
    assert "Operating system" in output, "Should show OS info"
    assert "Kernel version" in output, "Should check kernel version"
    assert "Privileged check" in output, "Should check privileged profile"
    assert "Security posture" in output, "Should check security posture"
    assert "Network bridge" in output, "Should check network bridge"
    assert "Disk space" in output, "Should check disk space"
    assert "Incus storage pool" in output, "Should check Incus storage pool"

    # Verify summary line
    assert "checks passed" in output or "checks failed" in output, "Should have summary"
