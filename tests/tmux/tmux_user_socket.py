"""
Regression tests for #588: coi tmux capture/send/list must exec as the
container's code user, not root.

tmux sessions are per-user (socket at /tmp/tmux-<uid>/default). The sessions
created by `coi shell --background` run as the code user, so helpers that
exec as root connect to /tmp/tmux-0 and fail (capture/send) or silently see
nothing (list). The pre-existing tmux tests masked this by creating their
sessions via a root `coi container exec` — root helpers against a root
session "worked", but that flow never happens in the product.

Covers:
1. Default code user (uid 1000 in coi-default)
2. A remapped code user (uid 501 — the [incus] code_uid / raw.idmap family
   from the issue report, simulated with usermod like
   remapContainerUserIfNeeded does)
3. That the helpers create no root tmux socket as a side effect
"""

import subprocess
import time

from support.helpers import calculate_container_name, launch_container


def run_coi(coi_binary, args, timeout=30):
    return subprocess.run(
        [coi_binary, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def create_session_as(coi_binary, container_name, uid):
    """Create the coi-<name> tmux session as the given uid, like the shell pipeline does."""
    tmux_session = f"coi-{container_name}"
    result = run_coi(
        coi_binary,
        [
            "container",
            "exec",
            container_name,
            "--user",
            str(uid),
            "--group",
            str(uid),
            "--",
            "tmux",
            "new-session",
            "-d",
            "-s",
            tmux_session,
            "bash",
        ],
    )
    assert result.returncode == 0, f"Session creation should succeed. stderr: {result.stderr}"
    time.sleep(1)
    return tmux_session


def assert_helpers_work(coi_binary, container_name, tmux_session, marker):
    # send must reach the code user's session
    result = run_coi(coi_binary, ["tmux", "send", container_name, f"echo {marker}"])
    assert result.returncode == 0, f"tmux send should succeed. stderr: {result.stderr}"
    time.sleep(1)

    # capture must return the pane contents including the marker
    result = run_coi(coi_binary, ["tmux", "capture", container_name])
    assert result.returncode == 0, f"tmux capture should succeed. stderr: {result.stderr}"
    assert marker in result.stdout, f"Captured pane should contain {marker}. Got:\n{result.stdout}"

    # list must see the session
    result = run_coi(coi_binary, ["tmux", "list"])
    assert result.returncode == 0, f"tmux list should succeed. stderr: {result.stderr}"
    assert container_name in result.stdout, (
        f"tmux list should show {container_name}. Got:\n{result.stdout}"
    )
    assert tmux_session in result.stdout, (
        f"tmux list should show session {tmux_session}. Got:\n{result.stdout}"
    )


def assert_no_root_socket(coi_binary, container_name):
    """A root-run tmux client creates /tmp/tmux-0 as a side effect — the
    helpers must never exec tmux as root, so the directory must not exist."""
    result = run_coi(
        coi_binary,
        ["container", "exec", container_name, "--", "test", "!", "-e", "/tmp/tmux-0"],
    )
    assert result.returncode == 0, (
        "/tmp/tmux-0 exists in the container — some helper ran tmux as root"
    )


def test_tmux_helpers_target_code_user_session(coi_binary, cleanup_containers, workspace_dir):
    """capture/send/list against a session owned by the default code user (uid 1000)."""
    container_name = calculate_container_name(workspace_dir, 1)
    launch_container(coi_binary, container_name)

    tmux_session = create_session_as(coi_binary, container_name, 1000)
    assert_helpers_work(coi_binary, container_name, tmux_session, "TMUX_588_CODE_USER")
    assert_no_root_socket(coi_binary, container_name)

    run_coi(coi_binary, ["container", "delete", container_name, "--force"])


def test_tmux_helpers_target_remapped_uid_session(coi_binary, cleanup_containers, workspace_dir):
    """capture/send/list when the code user was remapped to a non-default UID
    (the issue reporter's environment: host uid 501 -> usermod, as
    remapContainerUserIfNeeded does for [incus] code_uid)."""
    container_name = calculate_container_name(workspace_dir, 2)
    launch_container(coi_binary, container_name)

    # Remap exactly like internal/cli/run.go remapContainerUserIfNeeded
    result = run_coi(
        coi_binary,
        [
            "container",
            "exec",
            container_name,
            "--",
            "sh",
            "-c",
            "groupmod -g 501 code && usermod -u 501 -g 501 code && chown -R code:code /home/code",
        ],
        60,
    )
    assert result.returncode == 0, f"UID remap should succeed. stderr: {result.stderr}"

    tmux_session = create_session_as(coi_binary, container_name, 501)
    assert_helpers_work(coi_binary, container_name, tmux_session, "TMUX_588_REMAPPED_UID")
    assert_no_root_socket(coi_binary, container_name)

    run_coi(coi_binary, ["container", "delete", container_name, "--force"])
