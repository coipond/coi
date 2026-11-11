"""
Test for coi file pull - symlinks at the host destination or the container source.

Tests that:
1. A host destination that is a symlink is never written through:
   - `-r` refuses it (`already exists and is not a directory`)
   - a single-file pull replaces the link itself with a regular file
   The link's target (a sentinel outside the destination) stays unchanged.
2. A container source that is a symlink is refused by a single-file pull
   (`refusing to pull ...: not a regular file`) and nothing lands on the host.
"""

import os
import subprocess
import time

from support.helpers import calculate_container_name


def test_pull_symlink_destination_and_source(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that file pull never follows a host or container symlink.

    Flow:
    1. Launch a container with a regular file, a directory and a symlink
    2. Create a host symlink in the workspace to a sentinel outside it
    3. Pull -r onto the symlink: refused, sentinel unchanged
    4. Pull a single file onto the symlink: link replaced, sentinel unchanged
    5. Pull a container symlink as a single file: refused, nothing on the host
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
    setup = (
        "mkdir -p /tmp/symdest/dir && "
        f"echo '{pulled_content}' > /tmp/symdest/file.txt && "
        "echo nested > /tmp/symdest/dir/nested.txt && "
        "ln -s /etc/hostname /tmp/symdest/src-link"
    )
    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "sh", "-c", setup],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Setup should succeed. stderr: {result.stderr}"

    try:
        # === Phase 2: Host symlink to a sentinel outside the destination ===

        outside_dir = os.path.join(os.path.dirname(workspace_dir), "outside")
        os.makedirs(outside_dir, exist_ok=True)
        sentinel = os.path.join(outside_dir, "sentinel.txt")
        sentinel_content = "sentinel-must-not-change"
        with open(sentinel, "w") as f:
            f.write(sentinel_content)

        dest_link = os.path.join(workspace_dir, "dest-link")
        os.symlink(sentinel, dest_link)

        # === Phase 3: Recursive pull onto the symlink is refused ===

        result = subprocess.run(
            [coi_binary, "file", "pull", "-r", f"{container_name}:/tmp/symdest/dir", dest_link],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout + result.stderr

        # Should fail with exit code 2 (usage error)
        assert result.returncode == 2, (
            f"Recursive pull onto a symlink should fail with exit 2. output: {output}"
        )
        assert "already exists and is not a directory" in output, (
            f"Should report the existing non-directory. output: {output}"
        )
        assert os.path.islink(dest_link), "Refused pull should leave the host symlink in place"
        with open(sentinel) as f:
            assert f.read() == sentinel_content, "Refused pull must not touch the sentinel"
        assert os.listdir(outside_dir) == ["sentinel.txt"], (
            f"Nothing should land next to the sentinel. Got: {os.listdir(outside_dir)}"
        )

        # === Phase 4: Single-file pull replaces the symlink itself ===

        result = subprocess.run(
            [coi_binary, "file", "pull", f"{container_name}:/tmp/symdest/file.txt", dest_link],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Single-file pull should succeed. stderr: {result.stderr}"

        assert not os.path.islink(dest_link), "Pull should replace the symlink, not keep it"
        assert os.path.isfile(dest_link), "Pull should leave a regular file at the destination"
        with open(dest_link) as f:
            content = f.read()
        assert pulled_content in content, f"Destination should hold the pulled file. Got: {content}"
        with open(sentinel) as f:
            assert f.read() == sentinel_content, "Pull must never write through the symlink"

        # === Phase 5: Single-file pull of a container symlink is refused ===

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
        output = result.stdout + result.stderr

        assert result.returncode != 0, f"Pulling a container symlink should fail. output: {output}"
        assert "refusing to pull /tmp/symdest/src-link: not a regular file" in output, (
            f"Should refuse the non-regular source. output: {output}"
        )
        assert not os.path.lexists(local_target), (
            f"Nothing should be written on the host, but {local_target} exists"
        )
    finally:
        # === Phase 6: Cleanup ===

        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
