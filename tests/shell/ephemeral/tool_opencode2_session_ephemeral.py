"""
Test that coi sets up and launches the real opencode2 (OpenCode v2) the way
its session needs.

Tests that:
1. The host's v2 cli.json and opencode.json are copied into
   ~/.config/opencode; opencode.jsonc is not
2. Bypass mode launches opencode2 with --standalone --auto, interactive mode
   with --standalone only
3. No `opencode serve` process is left after the TUI exits
4. The saved session under ~/.coi/sessions-opencode2/ has no service.json
5. With --auto, a workspace V2 `ask` rule does not block a headless run

Each test uses a fake HOME, so the saved session and opencode2's tool-data
dirs land under tmp_path.
"""

import json
import shutil
import subprocess
import time
from pathlib import Path

from support.helpers import (
    calculate_container_name,
    exec_as_code_user,
    make_workspace_writable,
    poweroff_and_wait,
    spawn_coi,
    wait_for_container_ready,
    write_trusted_coi_config,
)

CONTAINER_CFG = "/home/code/.config/opencode"
HOST_CLI = {"$schema": "https://opencode.ai/v2/cli.json"}
HOST_OPENCODE = {"username": "coi-host-user"}

FAKE_SERVER = Path(__file__).resolve().parent.parent.parent / "support" / "fake_openai.py"

# A V2 rule in the workspace config that asks before every shell call. coi's
# V1 bypass in ~/.config/opencode/opencode.json does not override it; only
# --auto does.
WORKSPACE_ASK_RULE = {"permissions": [{"action": "shell", "resource": "*", "effect": "ask"}]}

SHELL_MARKER = ".opencode2-shell-ran"

# The server log stays out of /tmp (systemd-tmpfiles empties it).
WRAPPER = f"""#!/bin/sh
printf '%s\\n' "$@" > /workspace/.opencode2-args
python3 /workspace/.fake-openai.py 18080 'touch /workspace/{SHELL_MARKER}' \\
    > ~/fake-openai.log 2>&1 < /dev/null &
i=0
until python3 -c 'import socket; socket.create_connection(("127.0.0.1", 18080), 1)' \\
    2>/dev/null || [ "$i" -ge 150 ]; do
    i=$((i + 1))
    sleep 0.2
done
exec opencode2 "$@"
"""

FAKE_MODEL_CONFIG = {
    "model": "fake/fake",
    "provider": {
        "fake": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "Fake",
            "options": {"baseURL": "http://127.0.0.1:18080/v1", "apiKey": "x"},
            "models": {"fake": {"name": "fake"}},
        }
    },
}


def _fake_home(tmp_path):
    home = tmp_path / "fake_home"
    cfg = home / ".config" / "opencode"
    cfg.mkdir(parents=True)
    (cfg / "cli.json").write_text(json.dumps(HOST_CLI))
    (cfg / "opencode.json").write_text(json.dumps(HOST_OPENCODE))
    (cfg / "opencode.jsonc").write_text('// host jsonc\n{"username": "from-jsonc"}\n')
    return home


def _processes(container_name):
    return exec_as_code_user(container_name, "ps", "-eo", "args").stdout.splitlines()


def _opencode2_lines(container_name):
    """argv lines of the opencode2 process itself. The tmux server and the
    pane's `bash -c` also carry the launch command in their argv."""
    return [line for line in _processes(container_name) if line.split()[:1] == ["opencode2"]]


def _wait_for_opencode2(container_name, timeout=90):
    """Return the opencode2 TUI's argv line once it runs, else None."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = _opencode2_lines(container_name)
        if lines:
            return lines[0]
        time.sleep(1)
    return None


def _wait_for_opencode2_exit(container_name, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _opencode2_lines(container_name):
            return True
        time.sleep(1)
    return False


def _stop_opencode2(child, container_name, timeout=20):
    """Exit the TUI with Ctrl+C; SIGTERM it if it is still there."""
    child.send("\x03")
    time.sleep(1)
    child.send("\x03")
    if not _wait_for_opencode2_exit(container_name, timeout):
        exec_as_code_user(container_name, "pkill", "-TERM", "-f", "^opencode2 ")
        _wait_for_opencode2_exit(container_name, 10)


def test_opencode2_bypass_session(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    The real opencode2 TUI in bypass mode (the default).

    Flow:
    1. Fake HOME with v2 cli.json, opencode.json and opencode.jsonc
    2. coi shell with [tool] name = "opencode2"
    3. Read opencode2's argv and ~/.config/opencode in the container
    4. Exit the TUI; check no `opencode serve` process is left
    5. Write a service.json into ~/.config/opencode, as a v2 background
       service started by hand would
    6. Poweroff; check the saved session has the config but no service.json
    """
    fake_home = _fake_home(tmp_path)
    env = write_trusted_coi_config('[tool]\nname = "opencode2"\n')
    env.pop("COI_USE_DUMMY", None)
    env["HOME"] = str(fake_home)
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: launch ===
    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=90)
    argv = _wait_for_opencode2(container_name)

    cli = exec_as_code_user(container_name, "cat", f"{CONTAINER_CFG}/cli.json").stdout
    opencode = exec_as_code_user(container_name, "cat", f"{CONTAINER_CFG}/opencode.json").stdout
    listing = exec_as_code_user(container_name, "ls", "-a", CONTAINER_CFG).stdout.split()

    # === Phase 2: exit the TUI ===
    _stop_opencode2(child, container_name)
    after_exit = _processes(container_name)
    exec_as_code_user(
        container_name,
        "sh",
        "-c",
        f'echo \'{{"password": "secret"}}\' > {CONTAINER_CFG}/service.json',
    )

    # === Phase 3: poweroff saves the session ===
    poweroff_and_wait(child, coi_binary, container_name, timeout=90)

    assert argv, "coi shell should launch the real opencode2 TUI"
    flags = argv.split()[1:]
    assert "--standalone" in flags and "--auto" in flags, (
        f"bypass mode should launch opencode2 with --standalone --auto: {argv}"
    )

    assert json.loads(cli) == HOST_CLI, f"host cli.json was not copied: {cli}"
    assert json.loads(opencode).get("username") == HOST_OPENCODE["username"], (
        f"host opencode.json was not copied: {opencode}"
    )
    assert "opencode.jsonc" not in listing, (
        f"opencode.jsonc must not be copied into the container: {listing}"
    )

    serve = [line for line in after_exit if "opencode" in line and "serve" in line.split()]
    assert not serve, f"an opencode server outlived the TUI: {serve}"

    saved = list((fake_home / ".coi" / "sessions-opencode2").glob("*/.config/opencode"))
    assert len(saved) == 1, f"expected one saved opencode2 session, got {saved}"
    assert (saved[0] / "opencode.json").exists(), (
        f"the saved session should hold the config dir: {list(saved[0].iterdir())}"
    )
    assert not (saved[0] / "service.json").exists(), (
        "service.json (the v2 service password) must not be kept in a saved session"
    )


def test_opencode2_interactive_session(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    The real opencode2 TUI with [tool] permission_mode = "interactive" runs
    with --standalone but without --auto.

    Flow:
    1. coi shell --background with permission_mode = "interactive"
    2. Read opencode2's argv in the container
    """
    env = write_trusted_coi_config('[tool]\nname = "opencode2"\npermission_mode = "interactive"\n')
    env.pop("COI_USE_DUMMY", None)
    (tmp_path / "fake_home").mkdir()
    env["HOME"] = str(tmp_path / "fake_home")
    container_name = calculate_container_name(workspace_dir, 1)

    try:
        result = subprocess.run(
            [coi_binary, "shell", "--background", "--workspace", workspace_dir],
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
        assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
        argv = _wait_for_opencode2(container_name)
    finally:
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=60,
        )

    assert argv, "coi shell --background should launch the real opencode2 TUI"
    flags = argv.split()[1:]
    assert "--standalone" in flags, f"opencode2 should run with --standalone: {argv}"
    assert "--auto" not in flags, f"interactive mode must not pass --auto: {argv}"


def test_opencode2_auto_beats_workspace_ask_rule(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    A headless opencode2 run in bypass mode runs a shell call that a workspace
    V2 `ask` rule covers. Without --auto, opencode2 rejects the call (it
    cannot ask in a headless run) and the marker is never written.

    Flow:
    1. Workspace opencode.json with the ask rule; fake model server that
       answers with a shell call writing a marker
    2. coi run --prompt-file through a wrapper that starts the server, then
       execs the real opencode2 with coi's arguments
    3. Check the arguments and the marker
    """
    ws = Path(workspace_dir)
    (ws / "opencode.json").write_text(json.dumps(WORKSPACE_ASK_RULE))
    shutil.copy(FAKE_SERVER, ws / ".fake-openai.py")
    wrapper = ws / "opencode2-wrapper.sh"
    wrapper.write_text(WRAPPER)
    wrapper.chmod(0o755)
    make_workspace_writable(workspace_dir)
    prompt = tmp_path / "task.md"
    prompt.write_text("run the shell command\n")

    env = write_trusted_coi_config(
        '[tool]\nname = "opencode2"\nbinary = "/workspace/opencode2-wrapper.sh"\n\n'
        "[defaults.environment]\n"
        f"OPENCODE_CONFIG_CONTENT = '{json.dumps(FAKE_MODEL_CONFIG)}'\n"
    )
    env.pop("COI_USE_DUMMY", None)
    (tmp_path / "fake_home").mkdir()
    env["HOME"] = str(tmp_path / "fake_home")

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--prompt-file", str(prompt)],
        capture_output=True,
        text=True,
        timeout=300,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    output = result.stdout + result.stderr

    args = (ws / ".opencode2-args").read_text().splitlines()
    assert args[:1] == ["run"] and "--standalone" in args and "--auto" in args, (
        f"bypass mode should run `opencode2 run --standalone --auto`, got {args}"
    )
    assert result.returncode == 0, f"opencode2 run failed. output:\n{output}"
    assert (ws / SHELL_MARKER).exists(), (
        f"the workspace ask rule blocked the shell call despite --auto. output:\n{output}"
    )
