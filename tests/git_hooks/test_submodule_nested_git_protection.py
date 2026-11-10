"""
Submodule and nested-repo git dirs are read-only in the container at launch.

Host git reads a submodule's git dir (.git/modules/<name>) and nested repos on
a plain `git status` in the superproject, so their hooks and config are host
code execution sinks like the root .git. coi scans the workspace at launch and
protects them: submodule git dirs, and nested repos up to 3 levels below the
workspace root.

Tests that:
- hooks, config, config.worktree and info/attributes of a submodule git dir and
  of nested repos at depth 1 and 3 are read-only, and so is the submodule
  checkout's .git file
- a nested repo at depth 4 is not protected
- [git] writable_hooks = true leaves those hooks dirs writable, config read-only
- [security] writable_paths opts single nested entries out of protection
- [security] disable_protection leaves all of them writable
"""

import shlex
import subprocess
from pathlib import Path

from support.helpers import make_workspace_writable, run_coi_in_workspace, write_trusted_coi_config

GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "protocol.file.allow=always"]

SUBMODULE_GIT_DIR = ".git/modules/lib"
SUBMODULE_GIT_FILE = "lib/.git"
DEPTH1_GIT_DIR = "d1/.git"
DEPTH3_GIT_DIR = "x/y/d3/.git"
DEPTH4_GIT_DIR = "p/q/r/d4/.git"
PROTECTED_GIT_DIRS = (SUBMODULE_GIT_DIR, DEPTH1_GIT_DIR, DEPTH3_GIT_DIR)
GIT_DIR_ENTRIES = ("hooks", "config", "config.worktree", "info/attributes")


def _git_workspace(workspace_dir, tmp_path):
    """A repo with submodule lib and nested repos at depth 1, 3 and 4."""
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
    ws = Path(workspace_dir)
    for git_dir in (DEPTH1_GIT_DIR, DEPTH3_GIT_DIR, DEPTH4_GIT_DIR):
        repo = ws / git_dir[: -len("/.git")]
        repo.mkdir(parents=True)
        subprocess.run([*GIT, "init", "-q"], cwd=repo, check=True, capture_output=True)
    for git_dir in (*PROTECTED_GIT_DIRS, DEPTH4_GIT_DIR):
        (ws / git_dir / "hooks").mkdir(exist_ok=True)
    assert (ws / SUBMODULE_GIT_DIR / "HEAD").is_file()
    assert (ws / SUBMODULE_GIT_FILE).is_file()
    make_workspace_writable(workspace_dir)
    return ws


def _probe_writes(coi_binary, workspace_dir, paths, env=None):
    """Try a write to each path in one container run; return {path: (ok, error)}.

    A dir gets a new coi-probe file, a file an empty append.
    """
    ws = Path(workspace_dir)
    lines = []
    for rel in paths:
        target = shlex.quote(f"/workspace/{rel}")
        op = f"touch {target}/coi-probe" if (ws / rel).is_dir() else f": >> {target}"
        lines.append(
            f'if err=$( ({op}) 2>&1); then echo "OK {rel}"; else echo "ERR {rel} $err"; fi'
        )
    result = run_coi_in_workspace(
        coi_binary, workspace_dir, ["sh", "-c", "\n".join(lines)], env=env, timeout=180
    )
    assert result.returncode == 0, f"coi run failed: {result.stdout + result.stderr}"

    found = {}
    for line in (result.stdout + result.stderr).splitlines():
        status, _, rest = line.partition(" ")
        rel, _, error = rest.partition(" ")
        if status in ("OK", "ERR") and rel in paths:
            found[rel] = (status == "OK", error)
    assert set(found) == set(paths), f"missing probe results: {result.stdout + result.stderr}"
    return found


def _assert_read_only(ws, found, rel):
    ok, error = found[rel]
    assert not ok, f"{rel} must be read-only"
    assert "read-only file system" in error.lower(), (
        f"{rel}: expected read-only error, got: {error}"
    )
    assert not (ws / rel / "coi-probe").exists(), f"{rel}: probe written on the host"


def _assert_writable(ws, found, rel):
    ok, error = found[rel]
    assert ok, f"{rel} must be writable, got: {error}"
    if (ws / rel).is_dir():
        assert (ws / rel / "coi-probe").is_file(), f"{rel}: probe missing on the host"


def test_submodule_and_nested_git_read_only(
    coi_binary, workspace_dir, tmp_path, cleanup_containers
):
    """Submodule and nested git dirs up to depth 3 are read-only; depth 4 is not."""
    ws = _git_workspace(workspace_dir, tmp_path)
    protected = [f"{d}/{e}" for d in PROTECTED_GIT_DIRS for e in GIT_DIR_ENTRIES]
    protected.append(SUBMODULE_GIT_FILE)
    unprotected = [f"{DEPTH4_GIT_DIR}/hooks", f"{DEPTH4_GIT_DIR}/config"]

    found = _probe_writes(coi_binary, workspace_dir, protected + unprotected)

    for rel in protected:
        _assert_read_only(ws, found, rel)
    for rel in unprotected:
        _assert_writable(ws, found, rel)
    for entry in ("config.worktree", "info/attributes"):
        assert not (ws / DEPTH4_GIT_DIR / entry).exists(), f"depth 4 {entry} must not be created"


def test_writable_hooks_applies_to_nested_git(
    coi_binary, workspace_dir, tmp_path, cleanup_containers
):
    """writable_hooks leaves nested hooks dirs writable; config stays read-only."""
    ws = _git_workspace(workspace_dir, tmp_path)
    env = write_trusted_coi_config("[git]\nwritable_hooks = true\n")
    hooks = [f"{d}/hooks" for d in PROTECTED_GIT_DIRS]
    configs = [f"{d}/config" for d in PROTECTED_GIT_DIRS]

    found = _probe_writes(coi_binary, workspace_dir, hooks + configs, env=env)

    for rel in hooks:
        _assert_writable(ws, found, rel)
    for rel in configs:
        _assert_read_only(ws, found, rel)


def test_writable_paths_applies_to_nested_git(
    coi_binary, workspace_dir, tmp_path, cleanup_containers
):
    """writable_paths opts listed nested entries out; the others stay read-only."""
    ws = _git_workspace(workspace_dir, tmp_path)
    writable = [f"{SUBMODULE_GIT_DIR}/config", f"{DEPTH1_GIT_DIR}/hooks", SUBMODULE_GIT_FILE]
    listed = ", ".join(f'"{p}"' for p in writable)
    env = write_trusted_coi_config(f"[security]\nwritable_paths = [{listed}]\n")
    still_protected = [f"{SUBMODULE_GIT_DIR}/hooks", f"{DEPTH1_GIT_DIR}/config"]

    found = _probe_writes(coi_binary, workspace_dir, writable + still_protected, env=env)

    for rel in writable:
        _assert_writable(ws, found, rel)
    for rel in still_protected:
        _assert_read_only(ws, found, rel)


def test_disable_protection_applies_to_nested_git(
    coi_binary, workspace_dir, tmp_path, cleanup_containers
):
    """disable_protection leaves submodule and nested git dirs writable."""
    ws = _git_workspace(workspace_dir, tmp_path)
    env = write_trusted_coi_config("[security]\ndisable_protection = true\n")
    paths = [f"{d}/{e}" for d in PROTECTED_GIT_DIRS for e in ("hooks", "config")]
    paths.append(SUBMODULE_GIT_FILE)

    found = _probe_writes(coi_binary, workspace_dir, paths, env=env)

    for rel in paths:
        _assert_writable(ws, found, rel)
    for entry in ("config.worktree", "info/attributes"):
        assert not (ws / DEPTH1_GIT_DIR / entry).exists(), f"{entry} must not be created"
