"""
Test for coi run - a protected path that cannot be protected stops the run.

Tests that:
1. Incus refuses the read-only devices of two protected paths (.vscode and
   .husky): trusted [[mounts]] already use their container paths
2. coi run fails before the command runs
3. The error names both paths, so the failure at the first did not skip
   the second
"""

import subprocess

from support.helpers import write_trusted_coi_config

MARKER = "COMMAND_RAN_54888"


def test_run_protected_path_mount_failure(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    Test that coi run refuses to start without a protected path.

    Flow:
    1. Write a trusted config with writable mounts at /workspace/.vscode and
       /workspace/.husky
    2. coi run a command that prints a marker
    3. Verify the run fails, the marker is absent and the error names both
       paths
    """
    mounts = ""
    for name in ("vscode", "husky"):
        src = tmp_path / f"{name}-src"
        src.mkdir()
        mounts += f'\n[[mounts]]\nhost = "{src}"\ncontainer = "/workspace/.{name}"\n'
    env = write_trusted_coi_config(mounts)

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "echo", MARKER],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )

    combined = result.stdout + result.stderr
    assert result.returncode != 0, f"coi run must fail. Output:\n{combined}"
    assert MARKER not in result.stdout, f"command must not run. Output:\n{combined}"
    assert "cannot protect protected paths" in result.stderr, (
        f"expected the protection failure. stderr:\n{result.stderr}"
    )
    for path in (".vscode:", ".husky:"):
        assert path in result.stderr, f"error must name {path}. stderr:\n{result.stderr}"
