"""
Test for coi shell --container <missing> - error handling.

`--container NAME` attaches to an EXISTING container (it never creates one).
A non-existent name used to silently skip both the reuse and the creation
branches, then fail with a misleading "container not ready" only after the
full ready_timeout wait (~30s). It must instead fail FAST with a clear
"not found" error.
"""

import subprocess


def test_shell_container_not_found(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Run coi shell --container with a name that cannot exist
    2. Verify it exits 4 (container not found) quickly (no 30s ready_timeout hang)
    3. Verify the error names the missing container, not "not ready"
    """
    missing = "coi-does-not-exist-9c1f2a"

    result = subprocess.run(
        [
            coi_binary,
            "shell",
            "--workspace",
            workspace_dir,
            "--container",
            missing,
        ],
        capture_output=True,
        text=True,
        # Comfortably under the 30s ready_timeout the old misbehavior burned,
        # but generous enough for incus/image checks on a cold runner.
        timeout=25,
        cwd=workspace_dir,
    )

    # Exit 4 is coi's documented "targeted container does not exist" code.
    assert result.returncode == 4, (
        f"a missing --container must exit 4, got {result.returncode}. "
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    err = result.stderr + result.stdout
    assert missing in err, f"error should name the missing container. Got:\n{err}"
    assert "not found" in err, f"error should say the container was not found. Got:\n{err}"
    assert "not ready" not in err.lower(), (
        f"must not fall through to the misleading readiness-timeout error. Got:\n{err}"
    )
