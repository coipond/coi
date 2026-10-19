"""
Tests for coi file push -r when the destination name differs from the local
directory name.

The destination follows the same rules as coi file pull: an existing
directory receives the pushed directory inside it, a trailing slash requires
an existing directory, and any other destination is the exact target.
Each test pushes a local directory named "src" into its own container.
"""

import os
import subprocess
import time

from support.helpers import calculate_container_name


def _launch(coi_binary, workspace_dir):
    container_name = calculate_container_name(workspace_dir, 1)
    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"
    time.sleep(3)
    return container_name


def _make_src(workspace_dir):
    src = os.path.join(workspace_dir, "src")
    os.makedirs(os.path.join(src, "sub"), exist_ok=True)
    with open(os.path.join(src, "a.txt"), "w") as f:
        f.write("content-a-7f3")
    with open(os.path.join(src, "sub", "b.txt"), "w") as f:
        f.write("content-b-9c1")
    return src


def _push(coi_binary, src, destination):
    return subprocess.run(
        [coi_binary, "file", "push", "-r", src, destination],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _exec(coi_binary, container_name, *cmd):
    return subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", *cmd],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _assert_tree(coi_binary, container_name, root):
    for rel, content in (("a.txt", "content-a-7f3"), ("sub/b.txt", "content-b-9c1")):
        result = _exec(coi_binary, container_name, "cat", f"{root}/{rel}")
        assert result.returncode == 0, f"{root}/{rel} should exist. stderr: {result.stderr}"
        combined_output = result.stdout + result.stderr
        assert content in combined_output, (
            f"{root}/{rel} should hold the pushed content. Got:\n{combined_output}"
        )


def _delete(coi_binary, container_name):
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=60,
    )


def test_push_to_new_name_creates_that_path(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Push ./src to <c>:/tmp/renamed (does not exist)
    2. Verify /tmp/renamed holds the tree and /tmp/src was not created
    """
    container_name = _launch(coi_binary, workspace_dir)
    src = _make_src(workspace_dir)

    result = _push(coi_binary, src, f"{container_name}:/tmp/renamed")
    assert result.returncode == 0, f"push should succeed. stderr: {result.stderr}"

    _assert_tree(coi_binary, container_name, "/tmp/renamed")
    assert _exec(coi_binary, container_name, "test", "-e", "/tmp/src").returncode != 0, (
        "the push must not create /tmp/src"
    )
    assert _exec(coi_binary, container_name, "test", "-e", "/tmp/renamed/src").returncode != 0, (
        "the push must not nest src inside /tmp/renamed"
    )

    _delete(coi_binary, container_name)


def test_push_into_existing_dir(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Create /tmp/dest in the container
    2. Push ./src to <c>:/tmp/dest, then a second copy to <c>:/tmp/dest2/
       (also existing, with a trailing slash)
    3. Verify the tree lands at /tmp/dest/src and /tmp/dest2/src
    """
    container_name = _launch(coi_binary, workspace_dir)
    src = _make_src(workspace_dir)
    _exec(coi_binary, container_name, "mkdir", "-p", "/tmp/dest", "/tmp/dest2")

    result = _push(coi_binary, src, f"{container_name}:/tmp/dest")
    assert result.returncode == 0, f"push should succeed. stderr: {result.stderr}"
    _assert_tree(coi_binary, container_name, "/tmp/dest/src")

    result = _push(coi_binary, src, f"{container_name}:/tmp/dest2/")
    assert result.returncode == 0, f"push should succeed. stderr: {result.stderr}"
    _assert_tree(coi_binary, container_name, "/tmp/dest2/src")

    _delete(coi_binary, container_name)


def test_push_rejects_bad_destinations(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Push to a trailing-slash path that does not exist: exit 2, nothing created
    2. Push to an existing dir that already holds src: exit 2, nothing merged
    """
    container_name = _launch(coi_binary, workspace_dir)
    src = _make_src(workspace_dir)

    result = _push(coi_binary, src, f"{container_name}:/tmp/missing/")
    assert result.returncode == 2, (
        f"a trailing slash on a missing dir should exit 2, got {result.returncode}. "
        f"stderr: {result.stderr}"
    )
    assert "trailing slash" in result.stderr, f"Got:\n{result.stderr}"
    assert _exec(coi_binary, container_name, "test", "-e", "/tmp/missing").returncode != 0

    _exec(coi_binary, container_name, "mkdir", "-p", "/tmp/taken/src")
    result = _push(coi_binary, src, f"{container_name}:/tmp/taken")
    assert result.returncode == 2, (
        f"an existing final target should exit 2, got {result.returncode}. stderr: {result.stderr}"
    )
    assert "already exists" in result.stderr, f"Got:\n{result.stderr}"
    assert (
        _exec(coi_binary, container_name, "test", "-e", "/tmp/taken/src/a.txt").returncode != 0
    ), "nothing may be merged into the existing target"

    _delete(coi_binary, container_name)


def test_push_to_stopped_container(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Create /opt/dest, then stop the container (/opt, not /tmp: /tmp may
       be cleared when the container boots again)
    2. Push ./src to <c>:/opt/renamed and to <c>:/opt/dest (incus file
       push works on a stopped container, exec does not)
    3. Start the container and verify /opt/renamed and /opt/dest/src
    """
    container_name = _launch(coi_binary, workspace_dir)
    src = _make_src(workspace_dir)
    _exec(coi_binary, container_name, "mkdir", "-p", "/opt/dest")

    result = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"stop should succeed. stderr: {result.stderr}"

    for destination in ("/opt/renamed", "/opt/dest"):
        result = _push(coi_binary, src, f"{container_name}:{destination}")
        assert result.returncode == 0, (
            f"push to {destination} on a stopped container should succeed. stderr: {result.stderr}"
        )

    result = subprocess.run(
        [coi_binary, "container", "start", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"start should succeed. stderr: {result.stderr}"
    time.sleep(3)

    _assert_tree(coi_binary, container_name, "/opt/renamed")
    _assert_tree(coi_binary, container_name, "/opt/dest/src")

    _delete(coi_binary, container_name)
