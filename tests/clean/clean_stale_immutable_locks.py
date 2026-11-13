"""
Test for coi clean - clears stale immutable locks after coi is killed.

Tests that:
1. coi run applies immutable bits to protected paths and writes a manifest
2. SIGKILL of coi mid-session leaves the bits and the manifest behind
3. Once the container is gone, coi clean clears the bits, removes the
   manifest and reports "Cleaned N stale immutable lock(s)"
"""

import subprocess
import time
from pathlib import Path

import pytest

from support.helpers import (
    calculate_container_name,
    get_container_list,
    has_immutable_capability,
)

MANIFEST_DIR = Path.home() / ".coi" / "immutable-locks"


def _is_writable(path):
    try:
        with open(path, "a"):
            pass
    except PermissionError:
        return False
    return True


def _stale_manifest_count():
    containers = set(get_container_list())
    return sum(1 for m in MANIFEST_DIR.glob("*.json") if m.stem not in containers)


def test_clean_stale_immutable_locks(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    Test that coi clean clears immutable locks a killed coi left behind.

    Flow:
    1. Start coi run in a git workspace, wait for the immutable manifest
    2. SIGKILL coi, check the protected paths stay immutable
    3. Delete the container, run coi clean --force
    4. Verify the message, the manifest removal and writable paths
    """
    if not has_immutable_capability(coi_binary):
        pytest.skip(
            "coi binary lacks CAP_LINUX_IMMUTABLE "
            "(grant with: sudo setcap cap_linux_immutable=ep <coi-binary>)"
        )

    subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)
    pre_commit = Path(workspace_dir) / ".git" / "hooks" / "pre-commit"
    pre_commit.parent.mkdir(parents=True, exist_ok=True)
    pre_commit.write_text("#!/bin/sh\necho original\n")
    git_config = Path(workspace_dir) / ".git" / "config"

    container_name = calculate_container_name(workspace_dir, 1)
    manifest = MANIFEST_DIR / f"{container_name}.json"

    # === Phase 1: Start a session and wait for the immutable bits ===

    log_path = tmp_path / "coi-run.log"
    with open(log_path, "w") as log:
        # Output goes to a file: the orphaned incus exec keeps pipes open
        # after coi dies.
        proc = subprocess.Popen(
            [coi_binary, "run", "--workspace", workspace_dir, "--", "sleep", "600"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )

    try:
        deadline = time.monotonic() + 180
        running = False
        while time.monotonic() < deadline and proc.poll() is None:
            running = (
                manifest.exists()
                and subprocess.run(
                    [coi_binary, "container", "running", container_name],
                    capture_output=True,
                    timeout=10,
                ).returncode
                == 0
            )
            if running:
                break
            time.sleep(1)

        assert running, (
            f"Session should be running with a manifest at {manifest}. "
            f"coi run output: {log_path.read_text()}"
        )

        # === Phase 2: SIGKILL coi mid-session ===

        proc.kill()
        proc.wait(timeout=30)

        assert manifest.exists(), "SIGKILL should leave the manifest behind"
        assert not _is_writable(pre_commit), "pre-commit should stay immutable after SIGKILL"
        assert not _is_writable(git_config), ".git/config should stay immutable after SIGKILL"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)

        # === Phase 3: Remove the container, then clean ===
        # Runs on failure too: leaked +i bits make the workspace undeletable.

        delete = subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        expected = _stale_manifest_count()
        result = subprocess.run(
            [coi_binary, "clean", "--force"],
            capture_output=True,
            text=True,
            timeout=120,
        )

    # === Phase 4: Verify ===

    assert delete.returncode == 0, f"Container delete should succeed. stderr: {delete.stderr}"
    assert container_name not in get_container_list(), "Container should be gone before clean"
    assert result.returncode == 0, f"coi clean should succeed. stderr: {result.stderr}"

    output = result.stdout + result.stderr
    assert f"Cleaning stale immutable lock for {container_name}" in output, output
    assert f"Cleaned {expected} stale immutable lock(s)" in output, output
    assert not manifest.exists(), "coi clean should remove the manifest"

    assert _is_writable(pre_commit), "pre-commit should be writable after clean"
    assert _is_writable(git_config), ".git/config should be writable after clean"
    pre_commit.write_text("#!/bin/sh\necho modified\n")
    assert "modified" in pre_commit.read_text()
