"""
Test for coi file push / pull - both work on a stopped container.

Tests that:
1. Launch a container and create a file in it
2. Stop the container
3. Push a file to it and pull the existing file from it while it is stopped
4. Verify the pulled content, then start the container and verify the pushed file
"""

import os
import subprocess
import time

from support.helpers import calculate_container_name

PULL_CONTENT = "pull-from-stopped-container-7731"
PUSH_CONTENT = "push-to-stopped-container-7732"


def _exec(coi_binary, container_name, *command):
    return subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", *command],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_push_pull_stopped_container(coi_binary, cleanup_containers, workspace_dir):
    """
    Test pushing to and pulling from a stopped container.

    Flow:
    1. Launch a container, write /opt/pull-src.txt (/opt, not /tmp: /tmp may
       be cleared when the container boots again)
    2. Stop the container
    3. Push ./push-src.txt to /opt/pushed.txt and pull /opt/pull-src.txt
    4. Verify the pulled file, start the container, verify /opt/pushed.txt
    5. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container and create a file in it ===

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    result = _exec(
        coi_binary, container_name, "sh", "-c", f"echo {PULL_CONTENT} > /opt/pull-src.txt"
    )
    assert result.returncode == 0, f"File creation should succeed. stderr: {result.stderr}"

    # === Phase 2: Stop container ===

    result = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container stop should succeed. stderr: {result.stderr}"

    result = subprocess.run(
        [coi_binary, "container", "running", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0, "Container should be stopped before push/pull"

    # === Phase 3: Push and pull while stopped ===

    local_push = os.path.join(workspace_dir, "push-src.txt")
    with open(local_push, "w") as f:
        f.write(PUSH_CONTENT)

    result = subprocess.run(
        [coi_binary, "file", "push", local_push, f"{container_name}:/opt/pushed.txt"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"File push to a stopped container should succeed. stderr: {result.stderr}"
    )

    local_pull = os.path.join(workspace_dir, "pulled.txt")
    result = subprocess.run(
        [coi_binary, "file", "pull", f"{container_name}:/opt/pull-src.txt", local_pull],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"File pull from a stopped container should succeed. stderr: {result.stderr}"
    )

    # === Phase 4: Verify both files ===

    with open(local_pull) as f:
        pulled = f.read()
    assert PULL_CONTENT in pulled, f"Pulled content should match. Got: {pulled!r}"

    result = subprocess.run(
        [coi_binary, "container", "start", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container start should succeed. stderr: {result.stderr}"

    time.sleep(3)

    result = _exec(coi_binary, container_name, "cat", "/opt/pushed.txt")
    assert result.returncode == 0, f"Pushed file should exist. stderr: {result.stderr}"
    combined_output = result.stdout + result.stderr
    assert PUSH_CONTENT in combined_output, (
        f"Pushed content should match. Expected '{PUSH_CONTENT}', got:\n{combined_output}"
    )

    # === Phase 5: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
