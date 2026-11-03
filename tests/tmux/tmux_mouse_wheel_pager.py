"""
Test for the mouse wheel in a pager inside a coi-default tmux session.

Follow-up to https://github.com/coipond/coi/issues/930: with `mouse on` and
tmux's default wheel bindings, the wheel in a pager without mouse support
(less, man, git log) opened tmux copy mode instead of scrolling the pager.
The image's /etc/tmux.conf binds WheelUpPane/WheelDownPane to send Up/Down
keys to a pane on the alternate screen or with a pager in the foreground.

Tests that:
1. Wheel-down events on an attached client scroll `less` forward, without
   copy mode.
2. A wheel-up event scrolls `less` back, without copy mode.
3. `git log` with LESS unset (git runs less with -X, off the alternate
   screen) scrolls the same way.
4. A full-screen program that tracks the mouse gets the wheel events, not
   Up/Down keys.
5. At a shell prompt, wheel-up still enters copy mode.
"""

import subprocess
import time

from support.helpers import calculate_container_name, spawn_coi

WHEEL_UP = "\x1b[<64;10;5M"
WHEEL_DOWN = "\x1b[<65;10;5M"
REPO = "/home/code/wheel-repo"
MOUSE_INPUT = "/home/code/wheel-input"


def _exec(coi_binary, container_name, *args):
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--user",
            "1000",
            "--",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"{args[0]} should succeed. stderr: {result.stderr}"
    return result.stdout


def _tmux(coi_binary, container_name, *args):
    return _exec(coi_binary, container_name, "tmux", *args)


def _top_line(coi_binary, container_name, target):
    return _tmux(coi_binary, container_name, "capture-pane", "-p", "-t", target).splitlines()[0]


def _in_mode(coi_binary, container_name, target):
    return _tmux(coi_binary, container_name, "display", "-p", "-t", target, "#{pane_in_mode}")


def _new_session(coi_binary, container_name, session, command):
    _tmux(
        coi_binary,
        container_name,
        "new-session",
        "-d",
        "-s",
        session,
        "-x",
        "80",
        "-y",
        "20",
        command,
    )
    time.sleep(1)


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
    The wheel scrolls a pager in the pane, reaches a program that tracks the
    mouse, and leaves copy mode for the shell.

    Flow:
    1. Launch a container
    2. Start a tmux session running `seq 1 300 | less` and attach to it
    3. Send wheel-down events, check less moved forward and copy mode is off
    4. Send a wheel-up event, check less moved back and copy mode is off
    5. Same for `git log` with LESS unset in a 100-commit repo
    6. Start a program that turns on mouse tracking and records its input,
       send wheel events, check it got them as mouse events
    7. In a session with a shell, send wheel-up, check copy mode is on
    8. Cleanup
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
    _new_session(coi_binary, container_name, pager, "seq 1 300 | less")
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

    # === Phase 5: git log runs less off the alternate screen ===

    _exec(
        coi_binary,
        container_name,
        "env",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "bash",
        "-c",
        f"git init -q -b work {REPO} && for i in $(seq 1 100); do "
        f"git -C {REPO} -c user.name=t -c user.email=t@t "
        "-c core.hooksPath=/dev/null commit -q --allow-empty -m $i; done",
    )

    git_log = f"coi-{container_name}-gitlog"
    _new_session(coi_binary, container_name, git_log, f"env -u LESS git -C {REPO} log --format=%s")
    assert _top_line(coi_binary, container_name, git_log) == "100", (
        "git log should start at the newest commit"
    )

    child = _attach(coi_binary, container_name, git_log)
    time.sleep(2)
    for _ in range(3):
        child.send(WHEEL_DOWN)
    time.sleep(1)

    after_down = _top_line(coi_binary, container_name, git_log)
    assert _in_mode(coi_binary, container_name, git_log).strip() == "0", (
        "Wheel-down in git log must not enter copy mode"
    )
    assert after_down.isdigit() and int(after_down) < 100, (
        f"Wheel-down must scroll git log forward. Top line: {after_down!r}"
    )

    child.send(WHEEL_UP)
    time.sleep(1)

    after_up = _top_line(coi_binary, container_name, git_log)
    assert _in_mode(coi_binary, container_name, git_log).strip() == "0", (
        "Wheel-up in git log must not enter copy mode"
    )
    assert after_up.isdigit() and int(after_up) > int(after_down), (
        f"Wheel-up must scroll git log back. Top line: {after_up!r}, before: {after_down!r}"
    )

    child.close(force=True)

    # === Phase 6: A program that tracks the mouse gets the wheel events ===

    tracker = f"coi-{container_name}-tracker"
    _new_session(
        coi_binary,
        container_name,
        tracker,
        f"printf '\\033[?1049h\\033[?1000h\\033[?1006h'; stty raw -echo; cat > {MOUSE_INPUT}",
    )

    child = _attach(coi_binary, container_name, tracker)
    time.sleep(2)
    child.send(WHEEL_DOWN)
    child.send(WHEEL_UP)
    time.sleep(1)

    received = _exec(coi_binary, container_name, "cat", MOUSE_INPUT)
    assert received == WHEEL_DOWN + WHEEL_UP, (
        f"A program that tracks the mouse must get the wheel as mouse events. Got: {received!r}"
    )

    child.close(force=True)

    # === Phase 7: Wheel up at a shell prompt enters copy mode ===

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

    # === Phase 8: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
