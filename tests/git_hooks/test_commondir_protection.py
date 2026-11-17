"""
Test for coi run - .git/commondir is read-only.

git reads $GIT_DIR/commondir in every git dir and takes config and hooks from
the dir it names. Tests that:
1. coi materializes an absent .git/commondir with a placeholder naming the
   git dir itself (git refuses an empty commondir)
2. writing it from the container fails and the host file is unchanged
3. git still works in the container with the placeholder
"""

import subprocess
from pathlib import Path


def test_commondir_write_blocked(coi_binary, workspace_dir, cleanup_containers):
    """Writing /workspace/.git/commondir from inside the container must fail."""
    git = ["git", "-C", workspace_dir, "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True, capture_output=True)
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "init"], check=True)
    commondir = Path(workspace_dir) / ".git" / "commondir"
    assert not commondir.exists()

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            "echo ../x > /workspace/.git/commondir; rc=$?; "
            "git -C /workspace status --short && echo GIT_OK; exit $rc",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0, f"write should have failed; output: {combined}"
    assert "read-only" in combined or "read only" in combined or "permission denied" in combined, (
        f"expected read-only/permission error, got: {combined}"
    )
    assert "git_ok" in combined, f"git must work with the placeholder, got: {combined}"
    assert commondir.read_text() == "./\n", "host commondir must keep the placeholder"
    common = subprocess.run(
        [*git, "rev-parse", "--path-format=absolute", "--git-common-dir"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert Path(common).resolve() == (Path(workspace_dir) / ".git").resolve()
