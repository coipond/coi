"""
Test that `coi update patterns --dry-run` shows fetch and reset commands when both
clone directories already exist with a .git folder.
"""

import os
import subprocess


def test_update_patterns_dry_run_existing_clones(coi_binary, tmp_path):
    """
    Dry-run on a HOME where both databases already have a .git folder shows
    fetch and reset commands (not clone commands) for both, and exits 0.
    """
    # Create fake existing git repos at the default locations
    gtfobins_dir = tmp_path / ".coi" / "gtfobins"
    sigma_dir = tmp_path / ".coi" / "sigma"
    gtfobins_dir.mkdir(parents=True)
    sigma_dir.mkdir(parents=True)
    (gtfobins_dir / ".git").mkdir()
    (sigma_dir / ".git").mkdir()

    env = {**os.environ, "HOME": str(tmp_path)}

    result = subprocess.run(
        [coi_binary, "update", "patterns", "--dry-run"],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )

    assert result.returncode == 0, (
        f"Dry-run on existing clones should succeed. stderr: {result.stderr}"
    )
    output = result.stdout
    assert "[dry-run]" in output, f"Expected '[dry-run]' marker. Got:\n{output}"
    assert "fetch" in output and "reset" in output, (
        f"Existing clones should trigger fetch and reset commands. Got:\n{output}"
    )
    assert "clone" not in output, f"Existing clones should not re-clone. Got:\n{output}"
