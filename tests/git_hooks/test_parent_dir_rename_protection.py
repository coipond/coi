"""
A parent dir of a protected path cannot be renamed aside in the container.

A read-only mount moves with its parent dir when that dir is renamed. If the
container could rename .git (or a submodule's git dir under .git/modules) and
create the dir again, the new hooks/config would be writable and run on the
host. coi mounts each such parent dir over itself, so the rename fails.

Tests that:
- the root .git cannot be renamed and recreated with a hook
- a submodule git dir and .git/modules cannot be renamed and recreated
- the pinned parent dirs stay writable
"""

import subprocess
from pathlib import Path

from support.helpers import make_workspace_writable, run_coi_in_workspace

GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "protocol.file.allow=always"]


def _assert_rename_blocked(result):
    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0, f"rename should have failed; output: {combined}"
    assert "busy" in combined, f"expected 'Device or resource busy', got: {combined}"


def test_root_git_dir_rename_blocked(coi_binary, workspace_dir, cleanup_containers):
    """Renaming .git and recreating it with a hook fails; the host .git is intact."""
    subprocess.run([*GIT, "init", "-q"], cwd=workspace_dir, check=True, capture_output=True)
    make_workspace_writable(workspace_dir)
    ws = Path(workspace_dir)

    result = run_coi_in_workspace(
        coi_binary,
        workspace_dir,
        [
            "sh",
            "-c",
            "cd /workspace && mv .git .git.old && mkdir -p .git/hooks "
            "&& echo 'touch /tmp/pwned' > .git/hooks/pre-commit",
        ],
        timeout=180,
    )

    _assert_rename_blocked(result)
    assert not (ws / ".git.old").exists(), ".git must not have been renamed"
    assert not (ws / ".git" / "hooks" / "pre-commit").exists(), "hook must not be planted"
    assert (ws / ".git" / "HEAD").is_file(), "host .git must be intact"


def test_submodule_git_dir_rename_blocked(coi_binary, workspace_dir, tmp_path, cleanup_containers):
    """Renaming a submodule git dir, or .git/modules, and recreating it fails."""
    lib = tmp_path / "lib"
    lib.mkdir()
    for repo in (lib, Path(workspace_dir)):
        subprocess.run([*GIT, "init", "-q"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            [*GIT, "commit", "-q", "--allow-empty", "-m", "init"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
    subprocess.run(
        [*GIT, "submodule", "add", "-q", str(lib), "lib"],
        cwd=workspace_dir,
        check=True,
        capture_output=True,
    )
    make_workspace_writable(workspace_dir)
    modules = Path(workspace_dir) / ".git" / "modules"
    assert (modules / "lib" / "HEAD").is_file()

    for src in (".git/modules/lib", ".git/modules"):
        result = run_coi_in_workspace(
            coi_binary,
            workspace_dir,
            [
                "sh",
                "-c",
                f"cd /workspace && mv {src} {src}.old && mkdir -p .git/modules/lib/hooks "
                "&& echo 'touch /tmp/pwned' > .git/modules/lib/hooks/post-checkout",
            ],
            timeout=180,
        )

        _assert_rename_blocked(result)
        assert not (Path(workspace_dir) / f"{src}.old").exists(), f"{src} must not be renamed"
        assert not (modules / "lib" / "hooks" / "post-checkout").exists(), "hook planted"
        assert (modules / "lib" / "HEAD").is_file(), "submodule git dir must be intact"


def test_pinned_parent_dirs_stay_writable(coi_binary, workspace_dir, cleanup_containers):
    """Files in the pinned .git and .git/info can still be written."""
    subprocess.run([*GIT, "init", "-q"], cwd=workspace_dir, check=True, capture_output=True)
    make_workspace_writable(workspace_dir)
    git_dir = Path(workspace_dir) / ".git"

    result = run_coi_in_workspace(
        coi_binary,
        workspace_dir,
        [
            "sh",
            "-c",
            "echo probe > /workspace/.git/coi-probe && echo '*.tmp' > /workspace/.git/info/exclude",
        ],
        timeout=180,
    )

    assert result.returncode == 0, f"write failed: {result.stdout + result.stderr}"
    assert (git_dir / "coi-probe").read_text() == "probe\n"
    assert (git_dir / "info" / "exclude").read_text() == "*.tmp\n"
