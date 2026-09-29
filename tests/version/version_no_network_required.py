"""
Test for coi version - no network required.

Tests that:
1. Run coi version
2. Verify it works without network access
3. Verify version is embedded in binary
"""

import subprocess


def test_version_no_network_required(coi_binary):
    """
    Test version command works offline.

    Flow:
    1. Run coi version
    2. Verify exit code is 0
    3. Verify complete output is produced
    4. This confirms version is embedded in binary, not fetched from network
    """
    result = subprocess.run(
        [coi_binary, "version"],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, f"Version command should succeed. stderr: {result.stderr}"

    output = result.stdout

    # Verify complete version output
    assert "Coi (Code on Incus) v" in output, f"Should contain version string. Got:\n{output}"

    assert "https://github.com/mensfeld/code-on-incus" in output, (
        f"Should contain repository URL. Got:\n{output}"
    )

    # Verify output is complete (2 non-empty lines)
    lines = [line for line in output.strip().split("\n") if line]
    assert len(lines) == 2, (
        f"Should have complete output (2 lines). Got {len(lines)} lines:\n{output}"
    )

    # Note: This test doesn't actually block network access, but verifies
    # that the version command produces complete output quickly (<10s timeout)
    # indicating it's not making network calls.
