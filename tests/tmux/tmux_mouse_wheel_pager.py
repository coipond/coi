"""
Test for the mouse wheel in a pager inside a coi-default tmux session.

Follow-up to https://github.com/coipond/coi/issues/930: with `mouse on` and
tmux's default wheel bindings, the wheel in a pager without mouse support
(less, man, git log) opened tmux copy mode instead of scrolling the pager.
The image's /etc/tmux.conf binds WheelUpPane/WheelDownPane to send Up/Down
keys to a pane on the alternate screen.

Tests that:
1. Wheel-down events on an attached client scroll `less` forward, without
   copy mode.
2. A wheel-up event scrolls `less` back, without copy mode.
3. At a shell prompt, wheel-up still enters copy mode.
"""

import subprocess
import time

from support.helpers import calculate_container_name, spawn_coi

WHEEL_UP = "\x1b[<64;10;5M"
WHEEL_DOWN = "\x1b[<65;10;5M"


def _tmux(coi_binary, container_name, *args):
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--user",
            "1000",
            "--",
            "tmux",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"tmux {args[0]} should succeed. stderr: {result.stderr}"
    return result.stdout


def _top_line(coi_binary, container_name, target):
    return _tmux(coi_binary, container_name, "capture-pane", "-p", "-t", target).splitlines()[0]


def _in_mode(coi_binary, container_name, target):
    return _tmux(coi_binary, container_name, "display", "-p", "-t", target, "#{pane_in_mode}")


def _attach(coi_binary, container_name, session):
    return spawn_coi(
        coi_binary,
        [
            "container",
            "exec",
            container_name,
            "-t",
            "--user",
            "1000",
            "--",
            "env",
            "TERM=xterm-256color",
            "tmux",
            "attach",
            "-t",
            session,
        ],
    )


def test_tmux_mouse_wheel_scrolls_pager(coi_binary, cleanup_containers, workspace_dir):
    """
    The wheel scrolls a pager in the pane and leaves copy mode for the shell.

    Flow:
    1. Launch a container
    2. Start a tmux session running `seq 1 300 | less` and attach to it
    3. Send wheel-down events, check less moved forward and copy mode is off
    4. Send a wheel-up event, check less moved back and copy mode is off
    5. In a session with a shell, send wheel-up, check copy mode is on
    6. Cleanup
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

    # === Phase 2: less in an attached tmux session ===

    pager = f"coi-{container_name}-pager"
    _tmux(
        coi_binary,
        container_name,
        "new-session",
        "-d",
        "-s",
        pager,
        "-x",
        "80",
        "-y",
        "20",
        "seq 1 300 | less",
    )
    time.sleep(1)
    assert _top_line(coi_binary, container_name, pager) == "1", "less should start at line 1"

    child = _attach(coi_binary, container_name, pager)
    time.sleep(2)

    # === Phase 3: Wheel down scrolls less forward ===

    for _ in range(3):
        child.send(WHEEL_DOWN)
    time.sleep(1)

    after_down = _top_line(coi_binary, container_name, pager)
    assert _in_mode(coi_binary, container_name, pager).strip() == "0", (
        "Wheel-down in less must not enter copy mode"
    )
    assert after_down.isdigit() and int(after_down) > 1, (
        f"Wheel-down must scroll less forward. Top line: {after_down!r}"
    )

    # === Phase 4: Wheel up scrolls less back ===

    child.send(WHEEL_UP)
    time.sleep(1)

    after_up = _top_line(coi_binary, container_name, pager)
    assert _in_mode(coi_binary, container_name, pager).strip() == "0", (
        "Wheel-up in less must not enter copy mode"
    )
    assert after_up.isdigit() and int(after_up) < int(after_down), (
        f"Wheel-up must scroll less back. Top line: {after_up!r}, before: {after_down!r}"
    )

    child.close(force=True)

    # === Phase 5: Wheel up at a shell prompt enters copy mode ===

    shell = f"coi-{container_name}-shell"
    _tmux(coi_binary, container_name, "new-session", "-d", "-s", shell, "bash")
    time.sleep(1)

    child = _attach(coi_binary, container_name, shell)
    time.sleep(2)
    child.send(WHEEL_UP)
    time.sleep(1)

    assert _in_mode(coi_binary, container_name, shell).strip() == "1", (
        "Wheel-up at a shell prompt must enter copy mode"
    )

    child.close(force=True)

    # === Phase 6: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
