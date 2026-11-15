"""
Test for coi file pull -r - a relative container path is read from /.

Tests that:
1. `coi file pull -r <container>:tmp/<dir>` reads /tmp/<dir> from the named
   container (not from a container named `<container>tmp`)
2. The directory and its nested files land at the local destination
"""

import os
import subprocess
import time

from support.helpers import calculate_container_name


def test_pull_directory_relative_path(coi_binary, cleanup_containers, workspace_dir):
    """
    Test pulling a directory with a relative container path.

    Flow:
    1. Launch a container
    2. Create /tmp/pull-rel-test with nested files in the container
    3. Pull it with -r as `tmp/pull-rel-test` (no leading /)
    4. Verify the files exist locally
    5. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container ===

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    try:
        # === Phase 2: Create directory with files in container ===

        setup = (
            "mkdir -p /tmp/pull-rel-test/subdir && "
            "echo 'content-rel-file1' > /tmp/pull-rel-test/file1.txt && "
            "echo 'content-rel-file2' > /tmp/pull-rel-test/subdir/file2.txt"
        )
        result = subprocess.run(
            [coi_binary, "container", "exec", container_name, "--", "sh", "-c", setup],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Setup should succeed. stderr: {result.stderr}"

        # === Phase 3: Pull with a relative container path ===

        local_dir = os.path.join(workspace_dir, "pulled-rel-dir")
        result = subprocess.run(
            [coi_binary, "file", "pull", "-r", f"{container_name}:tmp/pull-rel-test", local_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout + result.stderr
        assert result.returncode == 0, f"Relative directory pull should succeed. output: {output}"
        assert "Instance not found" not in output, (
            f"Pull should address the named container. output: {output}"
        )

        # === Phase 4: Verify files exist locally ===

        file1_path = os.path.join(local_dir, "file1.txt")
        assert os.path.isfile(file1_path), f"file1.txt should exist at {file1_path}"
        with open(file1_path) as f:
            content = f.read()
        assert "content-rel-file1" in content, f"file1.txt content should match. Got: {content}"

        file2_path = os.path.join(local_dir, "subdir", "file2.txt")
        assert os.path.isfile(file2_path), f"subdir/file2.txt should exist at {file2_path}"
        with open(file2_path) as f:
            content = f.read()
        assert "content-rel-file2" in content, f"file2.txt content should match. Got: {content}"
    finally:
        # === Phase 5: Cleanup ===

        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
