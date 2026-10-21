"""
#875 regression: with `[git] readonly = true`, a persistent container mounts the
host file ~/.coi/git-identity/<hash>.gitconfig at ~/.gitconfig. If that file is
deleted while the container is stopped, the stale disk device would abort every
later start ("Failed to mount .../disk.git--identity...: No such file or
directory"). The pre-start device reconciler must drop the stale device, so the
container restarts and the identity step re-creates the file and mounts it again.

HOME points at a temp dir, so the identity file lives where the test can delete
it. COI_USE_DUMMY=1 keeps the tool binary out of the picture.
"""

import subprocess
import time

from support.helpers import calculate_container_name, write_trusted_coi_config

GIT_NAME = "Readonly Ident"
GIT_EMAIL = "readonly-ident@example.com"


def _incus_run(*args):
    return subprocess.run(
        ["incus", "--project", "default", *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _container_exists(name):
    return _incus_run("info", name).returncode == 0


def test_restart_after_git_identity_file_removed(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """Start a persistent session with a locked identity, stop it, delete the
    identity file on the host, and restart: the container comes up, no mount
    error, and the identity is mounted again."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    identity_dir = fake_home / ".coi" / "git-identity"

    env = write_trusted_coi_config(
        "[container]\npersistent = true\n\n"
        f'[git]\nname = "{GIT_NAME}"\nemail = "{GIT_EMAIL}"\nreadonly = true\n'
    )
    env["HOME"] = str(fake_home)
    env["COI_USE_DUMMY"] = "1"

    container_name = calculate_container_name(workspace_dir, 1)
    try:
        first = subprocess.run(
            [coi_binary, "shell", "--background"],
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
        assert first.returncode == 0, f"session 1 should succeed. stderr: {first.stderr}"
        time.sleep(2)
        assert _container_exists(container_name), f"expected {container_name} after session 1"
        identity_files = list(identity_dir.glob("*.gitconfig"))
        assert identity_files, f"expected a git-identity file under {identity_dir}"

        stop = subprocess.run(
            [coi_binary, "container", "stop", container_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert stop.returncode == 0, f"stop should succeed. stderr: {stop.stderr}"
        time.sleep(1)

        for f in identity_files:
            f.unlink()
        assert not list(identity_dir.glob("*.gitconfig"))

        resumed = subprocess.run(
            [coi_binary, "shell", "--container", container_name, "--background"],
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
        output = resumed.stdout + resumed.stderr
        assert resumed.returncode == 0, (
            f"the stopped container must restart after its identity file is gone. output:\n{output}"
        )
        assert "git--identity" not in output, f"start hit the stale mount. output:\n{output}"
        assert list(identity_dir.glob("*.gitconfig")), (
            f"the identity file should be re-created on the host. output:\n{output}"
        )

        # `coi container exec` routes the command's stdout to ITS stderr.
        exec_res = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "cat",
                "/home/code/.gitconfig",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        gitconfig = exec_res.stdout + exec_res.stderr
        assert GIT_NAME in gitconfig and GIT_EMAIL in gitconfig, (
            f"the locked identity should be mounted again. ~/.gitconfig:\n{gitconfig}"
        )
        assert "Managed by coi (git.readonly)" in gitconfig, (
            f"~/.gitconfig should be the coi-managed read-only file:\n{gitconfig}"
        )
    finally:
        _incus_run("delete", container_name, "--force")
