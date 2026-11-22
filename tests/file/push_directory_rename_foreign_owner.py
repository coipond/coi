"""
Test for coi file push -r - a renamed push keeps the owner of foreign-owned entries.

Tests that:
1. Launch a container
2. Create a local tree with a root-owned directory and file (via sudo)
3. Push it under another name, staged on another filesystem (TMPDIR=/dev/shm)
4. Verify each entry in the container has the host UID and GID
"""

import os
import subprocess
import time

import pytest

from support.helpers import calculate_container_name, exec_in


def test_push_directory_rename_foreign_owner(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that a non-root coi pushing a tree under another name keeps the
    owner of entries it does not own. coi cannot chown a copy to root, so
    the push must send the source entries themselves, whatever filesystem
    the host stage is on.

    Flow:
    1. Launch a container
    2. Create the local tree and make part of it root-owned
    3. Push it to a new name with the stage on /dev/shm
    4. Verify UID/GID of each entry with stat
    5. Cleanup
    """
    help_out = subprocess.run(
        ["incus", "file", "push", "--help"], capture_output=True, text=True, timeout=30
    )
    if "--follow" not in help_out.stdout:
        pytest.skip(
            "incus client without file push -H (pre-7.0): a renamed push sends a staged copy"
        )

    container_name = calculate_container_name(workspace_dir, 1)
    tree = os.path.join(workspace_dir, "push-owner-dir")
    owned = os.path.join(tree, "root-dir")

    try:
        # === Phase 1: Launch container ===

        result = subprocess.run(
            [coi_binary, "container", "launch", "coi-default", container_name],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

        time.sleep(3)

        # === Phase 2: Create the local tree, part of it root-owned ===

        os.makedirs(owned)
        for rel in ["mine.txt", "root-dir/root.txt"]:
            with open(os.path.join(tree, rel), "w") as f:
                f.write(f"{rel}\n")
        result = subprocess.run(
            ["sudo", "-n", "chown", "-R", "0:0", owned],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"sudo chown should succeed. stderr: {result.stderr}"

        expected = {}
        for rel in ["", "mine.txt", "root-dir", "root-dir/root.txt"]:
            st = os.stat(os.path.join(tree, rel))
            expected[rel] = f"{st.st_uid} {st.st_gid}"
        assert expected["root-dir/root.txt"] == "0 0", "Test setup: root.txt should be root-owned"
        assert expected["mine.txt"] != "0 0", "Test setup: tests must run as a non-root user"

        # === Phase 3: Push under another name, staged on another filesystem ===

        result = subprocess.run(
            [coi_binary, "file", "push", "-r", tree, f"{container_name}:/root/push-owner-renamed"],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "TMPDIR": "/dev/shm"},
        )
        assert result.returncode == 0, f"Push should succeed. stderr: {result.stderr}"

        # === Phase 4: Verify the owner of every entry ===

        for rel, want in expected.items():
            remote = f"/root/push-owner-renamed/{rel}" if rel else "/root/push-owner-renamed"
            code, output = exec_in(
                coi_binary, container_name, f"stat -c '%u %g' {remote}", timeout=30
            )
            assert code == 0, f"stat {remote} should succeed. output: {output}"
            assert output.strip() == want, (
                f"{remote} should keep host UID/GID '{want}', got: {output!r}"
            )
    finally:
        # === Phase 5: Cleanup ===

        subprocess.run(["sudo", "-n", "rm", "-rf", owned], capture_output=True, timeout=30)
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
