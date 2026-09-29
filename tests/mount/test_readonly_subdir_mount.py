"""Test readonly mount of a subdirectory inside a writable parent mount.

This tests the real-world scenario from issue #260: mounting ~/.claude/skills
(readonly) inside the writable ~/.claude directory that Coi manages. The readonly
subdirectory mount must overlay the parent writable mount correctly — reads should
work, writes should fail on the subdir, and the parent should remain writable.
"""

import os
import subprocess
from pathlib import Path


def test_readonly_subdir_inside_writable_parent_read(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """Test that a readonly subdir mount inside a writable parent allows reading."""
    # Simulate ~/.claude with a skills subdirectory
    claude_dir = tmp_path / "claude"
    claude_dir.mkdir()
    skills_dir = claude_dir / "skills"
    skills_dir.mkdir()
    (skills_dir / "my-skill.md").write_text("skill-content-here")
    (claude_dir / "settings.json").write_text('{"key": "value"}')

    config_content = f"""\
[[mounts.default]]
host = "{claude_dir}"
container = "/home/code/.testclaude"

[[mounts.default]]
host = "{skills_dir}"
container = "/home/code/.testclaude/skills"
readonly = true
"""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(config_content)

    # Verify both the parent file and the readonly subdir file are readable
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "sh",
            "-c",
            "cat /home/code/.testclaude/settings.json && "
            "cat /home/code/.testclaude/skills/my-skill.md",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "skill-content-here" in result.stdout
    assert '{"key": "value"}' in result.stdout


def test_readonly_subdir_inside_writable_parent_write_blocked(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """Test that writing to a readonly subdir mount fails while parent is writable."""
    claude_dir = tmp_path / "claude"
    claude_dir.mkdir()
    skills_dir = claude_dir / "skills"
    skills_dir.mkdir()
    (skills_dir / "existing-skill.md").write_text("do-not-modify")
    (claude_dir / "settings.json").write_text('{"key": "value"}')

    config_content = f"""\
[[mounts.default]]
host = "{claude_dir}"
container = "/home/code/.testclaude"

[[mounts.default]]
host = "{skills_dir}"
container = "/home/code/.testclaude/skills"
readonly = true
"""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(config_content)

    # Guard: verify the readonly mount is actually applied and readable
    read_result = subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "cat",
            "/home/code/.testclaude/skills/existing-skill.md",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
    )
    assert read_result.returncode == 0, (
        f"Mount should be present and readable.\n"
        f"stdout: {read_result.stdout}\nstderr: {read_result.stderr}"
    )
    assert "do-not-modify" in read_result.stdout

    # Attempt to write a new file in the readonly subdir — should fail
    write_result = subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "sh",
            "-c",
            "echo 'injected' > /home/code/.testclaude/skills/malicious.md",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
    )

    combined = write_result.stdout + write_result.stderr
    assert write_result.returncode != 0 or "read-only" in combined.lower(), (
        f"Write to readonly subdir mount should have failed.\n"
        f"returncode: {write_result.returncode}\n"
        f"stdout: {write_result.stdout}\n"
        f"stderr: {write_result.stderr}"
    )

    # Verify host files were not modified
    assert (skills_dir / "existing-skill.md").read_text() == "do-not-modify"
    assert not (skills_dir / "malicious.md").exists()


def test_readonly_subdir_parent_still_writable(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """Test that the writable parent mount remains writable when a subdir is readonly."""
    claude_dir = tmp_path / "claude"
    claude_dir.mkdir()
    skills_dir = claude_dir / "skills"
    skills_dir.mkdir()
    (skills_dir / "skill.md").write_text("read-only-skill")

    # Ensure the container user can write to the parent mount directory
    os.chmod(claude_dir, 0o777)

    config_content = f"""\
[[mounts.default]]
host = "{claude_dir}"
container = "/home/code/.testclaude"

[[mounts.default]]
host = "{skills_dir}"
container = "/home/code/.testclaude/skills"
readonly = true
"""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(config_content)

    # Write to the parent directory (outside the readonly subdir) — should succeed
    write_result = subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "sh",
            "-c",
            "echo 'new-file' > /home/code/.testclaude/writable-test.txt && "
            "cat /home/code/.testclaude/writable-test.txt",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
    )

    assert write_result.returncode == 0, (
        f"Write to writable parent should succeed.\n"
        f"stdout: {write_result.stdout}\nstderr: {write_result.stderr}"
    )
    assert "new-file" in write_result.stdout

    # Verify the readonly subdir is still read-only in the same scenario
    ro_result = subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "sh",
            "-c",
            "echo 'bad' > /home/code/.testclaude/skills/injected.md",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
    )

    combined = ro_result.stdout + ro_result.stderr
    assert ro_result.returncode != 0 or "read-only" in combined.lower(), (
        f"Write to readonly subdir should still fail.\n"
        f"returncode: {ro_result.returncode}\n"
        f"stdout: {ro_result.stdout}\n"
        f"stderr: {ro_result.stderr}"
    )
    assert not (skills_dir / "injected.md").exists()


def test_writable_mount_allows_writing(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """Test that a mount without readonly allows writing (control test).

    This is the inverse of the readonly tests above: when a mount does NOT set
    readonly = true, writes should succeed. Confirms that the readonly flag is
    what actually blocks writes, not anything else about the mount setup.
    """
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "existing.md").write_text("original-content")

    # Ensure the container user can write
    os.chmod(skills_dir, 0o777)

    config_content = f"""\
[[mounts.default]]
host = "{skills_dir}"
container = "/home/code/.testskills"
"""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(config_content)

    # Write to the mount — should succeed since readonly is not set
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--",
            "sh",
            "-c",
            "echo 'written-ok' > /home/code/.testskills/new-file.md && "
            "cat /home/code/.testskills/new-file.md",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, (
        f"Write to writable mount should succeed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "written-ok" in result.stdout

    # Verify the file was created on the host
    assert (skills_dir / "new-file.md").exists()
