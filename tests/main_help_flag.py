"""
Test main CLI --help flag.

Expected:
- Help text is displayed
- Exit code is 0
"""

import subprocess


def test_main_help_flag(coi_binary):
    """Test that coi --help displays help text."""
    result = subprocess.run([coi_binary, "--help"], capture_output=True, text=True, timeout=5)

    assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}"
    assert "coi (code on incus)" in result.stdout.lower()
    assert "usage:" in result.stdout.lower() or "examples:" in result.stdout.lower()
