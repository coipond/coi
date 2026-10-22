"""
Test for coi clean --sessions --dry-run - lists saved sessions but deletes nothing.

Tests that:
1. Create a saved session directory under ~/.coi/sessions-claude
2. Run coi clean --sessions --dry-run
3. Verify the session is listed and "[Dry run] No changes made." is printed
4. Verify the session data still exists
"""

import os
import shutil
import subprocess
from pathlib import Path


def test_clean_sessions_dry_run(coi_binary):
    """
    Test that 'coi clean --sessions --dry-run' lists saved sessions and keeps them.

    Flow:
    1. Create a saved session directory under ~/.coi/sessions-claude
    2. Run coi clean --sessions --dry-run
    3. Verify the session is listed and the dry-run line is printed
    4. Verify the session directory and its data still exist
    5. Cleanup
    """
    session_name = f"coi-test-dryrun-session-{os.urandom(4).hex()}"
    session_dir = Path.home() / ".coi" / "sessions-claude" / session_name
    session_dir.mkdir(parents=True)
    marker = session_dir / "metadata.json"
    marker.write_text("{}\n")

    try:
        # === Phase 1: Dry run ===
        result = subprocess.run(
            [coi_binary, "clean", "--sessions", "--dry-run"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"coi clean --sessions --dry-run should succeed. stderr: {result.stderr}"
        )
        assert f"  - {session_name}" in result.stdout, (
            f"Dry run should list the saved session. stdout:\n{result.stdout}"
        )
        assert "[Dry run] No changes made." in result.stdout, (
            f"Dry run should say nothing changed. stdout:\n{result.stdout}"
        )
        assert "Deleting session" not in result.stdout, (
            f"Dry run should not delete anything. stdout:\n{result.stdout}"
        )

        # === Phase 2: Session data is still there ===
        assert marker.exists(), f"Session data {marker} should survive a dry run"
    finally:
        # === Cleanup ===
        shutil.rmtree(session_dir, ignore_errors=True)
