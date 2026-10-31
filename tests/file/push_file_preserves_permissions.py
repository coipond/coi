"""
Test for coi file push - pushed file keeps its host mode and owner.

Tests that:
1. Launch a container
2. Create a local file with mode 0755
3. Push file to container
4. Verify the file in the container has the host mode, UID and GID, and runs
"""

import os
import subprocess
import time

from support.helpers import calculate_container_name

MARKER = "push-permissions-ran-4417"


def test_push_file_preserves_permissions(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that a pushed file keeps the mode, UID and GID it has on the host.

    Flow:
    1. Launch a container
    2. Create an executable script locally (mode 0755)
    3. Push it to the container
    4. Verify mode/UID/GID with stat and run it
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

    # === Phase 2: Create local executable file ===

    local_file = os.path.join(workspace_dir, "push-perm.sh")
    with open(local_file, "w") as f:
        f.write(f"#!/bin/sh\necho {MARKER}\n")
    os.chmod(local_file, 0o755)
    host_stat = os.stat(local_file)

    # === Phase 3: Push file to container ===

    result = subprocess.run(
        [coi_binary, "file", "push", local_file, f"{container_name}:/tmp/push-perm.sh"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"File push should succeed. stderr: {result.stderr}"

    # === Phase 4: Verify mode, owner, and that it runs ===

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "stat",
            "-c",
            "%a %u %g",
            "/tmp/push-perm.sh",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stat should succeed. stderr: {result.stderr}"

    expected = f"755 {host_stat.st_uid} {host_stat.st_gid}"
    combined_output = result.stdout + result.stderr
    assert expected in combined_output, (
        f"Pushed file should keep host mode/UID/GID '{expected}', got:\n{combined_output}"
    )

    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "/tmp/push-perm.sh"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Pushed script should run. stderr: {result.stderr}"
    assert MARKER in result.stdout + result.stderr, (
        f"Pushed script should print its marker. Got:\n{result.stdout}{result.stderr}"
    )

    # === Phase 5: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
