"""
Integration tests for #1045: in bypass mode, OpenCode v1 runs a tool call
that an `ask` permission rule covers.

coi's `"permission": {"*": "allow"}` in ~/.config/opencode/opencode.json loses
to a more specific `ask` rule, since OpenCode applies the last matching rule:
the TUI then asked for confirmation, and `opencode run` rejected the call. coi
now passes --auto, which approves every request that is not explicitly denied.

Each test runs the real `opencode run` from the default image against a fake
OpenAI-compatible model in the container, which answers with a `bash` tool
call that writes a marker file. Interactive mode is not covered here:
`coi run --prompt` refuses it before the launch.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from support.helpers import make_workspace_writable, write_trusted_coi_config

FAKE_SERVER = Path(__file__).resolve().parent.parent / "support" / "fake_openai.py"

# Asks before every shell call. In the host config, coi's merge keeps it next
# to its "*" rule, and writes it after "*".
ASK_RULE = {"permission": {"bash": "ask"}}

SHELL_MARKER = ".opencode-shell-ran"

# Starts the fake model, then execs the real opencode with coi's arguments.
# The server log stays out of /tmp (systemd-tmpfiles empties it).
WRAPPER = f"""#!/bin/sh
printf '%s\\n' "$@" > /workspace/.opencode-args
python3 /workspace/.fake-openai.py 18080 'touch /workspace/{SHELL_MARKER}' bash \\
    > ~/fake-openai.log 2>&1 < /dev/null &
i=0
until python3 -c 'import socket; socket.create_connection(("127.0.0.1", 18080), 1)' \\
    2>/dev/null || [ "$i" -ge 150 ]; do
    i=$((i + 1))
    sleep 0.2
done
exec opencode "$@"
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


def _run_opencode(coi_binary, workspace_dir, tmp_path, rule_in):
    """Run `coi run --prompt-file` with the ask rule in the host config
    ("host") or the workspace ("workspace"). Returns (result, opencode args)."""
    ws = Path(workspace_dir)
    shutil.copy(FAKE_SERVER, ws / ".fake-openai.py")
    wrapper = ws / "opencode-wrapper.sh"
    wrapper.write_text(WRAPPER)
    wrapper.chmod(0o755)

    fake_home = tmp_path / "fake_home"
    host_cfg = fake_home / ".config" / "opencode"
    host_cfg.mkdir(parents=True)
    if rule_in == "host":
        (host_cfg / "opencode.json").write_text(json.dumps(ASK_RULE))
    else:
        (ws / "opencode.json").write_text(json.dumps(ASK_RULE))
    make_workspace_writable(workspace_dir)

    prompt = tmp_path / "task.md"
    prompt.write_text("run the shell command\n")

    env = write_trusted_coi_config(
        '[tool]\nname = "opencode"\nbinary = "/workspace/opencode-wrapper.sh"\n\n'
        "[defaults.environment]\n"
        f"OPENCODE_CONFIG_CONTENT = '{json.dumps(FAKE_MODEL_CONFIG)}'\n"
    )
    env.pop("COI_USE_DUMMY", None)
    env["HOME"] = str(fake_home)

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--prompt-file", str(prompt)],
        capture_output=True,
        text=True,
        timeout=300,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    args = (ws / ".opencode-args").read_text().splitlines()
    return result, args


@pytest.mark.parametrize("rule_in", ["host", "workspace"])
def test_opencode_auto_beats_ask_rule(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, rule_in
):
    """Bypass mode (the default) runs `opencode run --auto`, and the shell
    call that the ask rule covers runs."""
    result, args = _run_opencode(coi_binary, workspace_dir, tmp_path, rule_in)
    output = result.stdout + result.stderr

    assert args[:2] == ["run", "--auto"], (
        f"bypass mode should run `opencode run --auto`, got {args}"
    )
    assert result.returncode == 0, f"opencode run failed. output:\n{output}"
    assert (Path(workspace_dir) / SHELL_MARKER).exists(), (
        f"the {rule_in} ask rule blocked the shell call despite --auto. output:\n{output}"
    )
