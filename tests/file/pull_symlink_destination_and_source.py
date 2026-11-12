"""
Test for coi file pull - symlinks at the host destination or the container source.

Tests that:
1. A host destination that is a symlink is never written through, whether it
   points to a file or a directory outside the workspace:
   - `-r` refuses it (`already exists and is not a directory`)
   - a single-file pull replaces the link itself with a regular file
   Nothing lands in, and nothing changes under, the links' targets.
2. A container source that is a symlink is pulled as a regular file with the
   link target's content (incus dereferences it inside the container); no
   symlink is created on the host.
"""

import os
import subprocess
import time

from support.helpers import calculate_container_name


def test_pull_symlink_destination_and_source(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that file pull never follows a host symlink nor creates one.

    Flow:
    1. Launch a container with a regular file, a directory and a symlink
    2. Create host symlinks in the workspace to a file and a directory outside it
    3. Pull -r onto each symlink: refused, targets unchanged
    4. Pull a single file onto each symlink: links replaced, targets unchanged
    5. Pull a container symlink as a single file: regular file on the host
    6. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container and create sources ===

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    pulled_content = "pulled-from-container-48213"
    link_target_content = "container-link-target-73519"
    setup = (
        "mkdir -p /tmp/symdest/dir && "
        f"echo '{pulled_content}' > /tmp/symdest/file.txt && "
        "echo nested > /tmp/symdest/dir/nested.txt && "
        f"echo '{link_target_content}' > /tmp/link-target.txt && "
        "ln -s /tmp/link-target.txt /tmp/symdest/src-link"
    )
    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "sh", "-c", setup],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Setup should succeed. stderr: {result.stderr}"

    try:
        # === Phase 2: Host symlinks to a file and a directory outside the workspace ===

        outside_dir = os.path.join(os.path.dirname(workspace_dir), "outside")
        os.makedirs(outside_dir, exist_ok=True)
        sentinel = os.path.join(outside_dir, "sentinel.txt")
        sentinel_content = "sentinel-must-not-change"
        with open(sentinel, "w") as f:
            f.write(sentinel_content)

        file_link = os.path.join(workspace_dir, "file-link")
        os.symlink(sentinel, file_link)
        dir_link = os.path.join(workspace_dir, "dir-link")
        os.symlink(outside_dir, dir_link)

        def assert_outside_untouched(step):
            assert os.listdir(outside_dir) == ["sentinel.txt"], (
                f"{step}: nothing should land outside the workspace. Got: {os.listdir(outside_dir)}"
            )
            with open(sentinel) as f:
                assert f.read() == sentinel_content, f"{step}: the sentinel must not change"

        # === Phase 3: Recursive pull onto each symlink is refused ===

        for link in (file_link, dir_link):
            result = subprocess.run(
                [coi_binary, "file", "pull", "-r", f"{container_name}:/tmp/symdest/dir", link],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout + result.stderr

            # Should fail with exit code 2 (usage error)
            assert result.returncode == 2, (
                f"Recursive pull onto {link} should fail with exit 2. output: {output}"
            )
            assert "already exists and is not a directory" in output, (
                f"Should report the existing non-directory. output: {output}"
            )
            assert os.path.islink(link), f"Refused pull should leave {link} in place"
            assert_outside_untouched(f"pull -r onto {link}")

        # === Phase 4: Single-file pull replaces each symlink itself ===

        for link in (file_link, dir_link):
            result = subprocess.run(
                [coi_binary, "file", "pull", f"{container_name}:/tmp/symdest/file.txt", link],
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Single-file pull onto {link} should succeed. stderr: {result.stderr}"
            )

            assert not os.path.islink(link), f"Pull should replace {link}, not keep it"
            assert os.path.isfile(link), f"Pull should leave a regular file at {link}"
            with open(link) as f:
                content = f.read()
            assert pulled_content in content, f"{link} should hold the pulled file. Got: {content}"
            assert_outside_untouched(f"pull onto {link}")

        # === Phase 5: Single-file pull of a container symlink ===

        local_target = os.path.join(workspace_dir, "from-src-link")
        result = subprocess.run(
            [
                coi_binary,
                "file",
                "pull",
                f"{container_name}:/tmp/symdest/src-link",
                local_target,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Pulling a container symlink should succeed. stderr: {result.stderr}"
        )

        assert not os.path.islink(local_target), "No symlink should be created on the host"
        assert os.path.isfile(local_target), "The pull should leave a regular file"
        with open(local_target) as f:
            content = f.read()
        assert link_target_content in content, (
            f"The file should hold the link target's content. Got: {content}"
        )
    finally:
        # === Phase 6: Cleanup ===

        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
