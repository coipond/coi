"""
Test main CLI -h shorthand.

Expected:
- -h works as shorthand for --help
"""

import subprocess


def test_main_help_shorthand(coi_binary):
    """Test that coi -h works as shorthand for --help."""
    result = subprocess.run([coi_binary, "-h"], capture_output=True, text=True, timeout=5)

    assert result.returncode == 0
    assert "coi (code on incus)" in result.stdout.lower()
