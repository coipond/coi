"""
Test what `[tool] permission_mode = "interactive"` changes inside the container
for claude, opencode and codex (#186, #649, #764).

Under the default (bypass) mode coi injects settings and flags that skip each
tool's permission prompts. Under interactive mode it must leave the prompts on:

  * claude: no bypass keys in ~/.claude/settings.json, and no `disableAutoMode`
    in /etc/claude-code/managed-settings.json (#764);
  * opencode: `"permission": {"*": "ask"}` in opencode.json;
  * codex: launched with `-s workspace-write -a on-request`.

Each test starts `coi shell --background` and then reads the result from the
running container (or, for codex, from a workspace marker file). The config is
supplied in TRUSTED scope (COI_CONFIG). claude only seeds its config when the
host has a ~/.claude dir, so the claude tests use a fake HOME that has one.
"""

import json
import subprocess
import time
from pathlib import Path

from support.helpers import calculate_container_name, write_trusted_coi_config

CLAUDE_SETTINGS = "/home/code/.claude/settings.json"
CLAUDE_MANAGED_SETTINGS = "/etc/claude-code/managed-settings.json"
OPENCODE_SETTINGS = "/home/code/.config/opencode/opencode.json"

CLAUDE_BYPASS_KEYS = (
    "allowDangerouslySkipPermissions",
    "bypassPermissionsModeAccepted",
    "skipDangerousModePermissionPrompt",
)

MARKER = ".coi-codex-argv-marker"

FAKE_CODEX = f"""#!/bin/sh
# Stand-in for codex: record how coi launched us, then stay alive.
printf '%s\\n' "$@" > "$(dirname "$0")/{MARKER}"
exec sleep 300
"""


def _start_background_shell(coi_binary, workspace_dir, env):
    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
    return calculate_container_name(workspace_dir, 1)


def _read_container_file(container_name, path):
    """Return the file's content, or None when it does not exist."""
    result = subprocess.run(
        ["incus", "exec", container_name, "--", "cat", path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout if result.returncode == 0 else None


def _claude_env(tmp_path, permission_mode):
    fake_home = tmp_path / "fake_home"
    (fake_home / ".claude").mkdir(parents=True)
    config = '[tool]\nname = "claude"\n'
    if permission_mode:
        config += f'permission_mode = "{permission_mode}"\n'
    env = write_trusted_coi_config(config)
    env["HOME"] = str(fake_home)
    env["COI_USE_DUMMY"] = "1"
    return env


def test_claude_interactive_has_no_bypass_settings(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    Under interactive mode claude gets no bypass settings and no auto-mode
    suppression policy.

    Flow:
    1. Configure tool=claude, permission_mode=interactive; fake HOME with ~/.claude
    2. Start `coi shell --background` with COI_USE_DUMMY
    3. Assert settings.json was written (effort keys) and has none of the
       bypass keys and no permissions.defaultMode
    4. Assert managed-settings.json, if written, has no disableAutoMode
    """
    container_name = _start_background_shell(
        coi_binary, workspace_dir, _claude_env(tmp_path, "interactive")
    )

    content = _read_container_file(container_name, CLAUDE_SETTINGS)
    assert content is not None, f"{CLAUDE_SETTINGS} was not written"
    settings = json.loads(content)
    assert settings.get("effortLevelAccepted") is True, (
        f"sandbox settings were not merged into settings.json: {settings}"
    )
    for key in CLAUDE_BYPASS_KEYS:
        assert key not in settings, f"interactive mode must not inject {key}: {settings}"
    assert "defaultMode" not in settings.get("permissions", {}), (
        f"interactive mode must not set permissions.defaultMode: {settings}"
    )

    managed = _read_container_file(container_name, CLAUDE_MANAGED_SETTINGS)
    if managed is not None:
        assert "disableAutoMode" not in json.loads(managed), (
            f"interactive mode must not write disableAutoMode (#764): {managed}"
        )


def test_claude_bypass_control_has_bypass_settings(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    Control: under the default (bypass) mode the same setup writes the bypass
    settings, with skipDangerousModePermissionPrompt at the top level (#649),
    and the disableAutoMode policy.

    Flow:
    1. Configure tool=claude, no permission_mode; fake HOME with ~/.claude
    2. Start `coi shell --background` with COI_USE_DUMMY
    3. Assert settings.json has the bypass keys at the top level, not under
       permissions, and permissions.defaultMode = bypassPermissions
    4. Assert managed-settings.json has disableAutoMode
    """
    container_name = _start_background_shell(coi_binary, workspace_dir, _claude_env(tmp_path, None))

    content = _read_container_file(container_name, CLAUDE_SETTINGS)
    assert content is not None, f"{CLAUDE_SETTINGS} was not written"
    settings = json.loads(content)
    for key in CLAUDE_BYPASS_KEYS:
        assert settings.get(key) is True, f"bypass mode must set top-level {key}: {settings}"
    permissions = settings.get("permissions", {})
    assert "skipDangerousModePermissionPrompt" not in permissions, (
        f"skipDangerousModePermissionPrompt belongs at the top level (#649): {settings}"
    )
    assert permissions.get("defaultMode") == "bypassPermissions", (
        f"bypass mode must set permissions.defaultMode: {settings}"
    )

    managed = _read_container_file(container_name, CLAUDE_MANAGED_SETTINGS)
    assert managed is not None, f"{CLAUDE_MANAGED_SETTINGS} was not written"
    assert json.loads(managed).get("disableAutoMode") == "disable", managed


def test_opencode_interactive_asks_for_permission(coi_binary, cleanup_containers, workspace_dir):
    """
    Under interactive mode opencode.json sets every permission to "ask".

    Flow:
    1. Configure tool=opencode, permission_mode=interactive
    2. Start `coi shell --background` with COI_USE_DUMMY
    3. Assert opencode.json has {"permission": {"*": "ask"}}
    """
    env = write_trusted_coi_config('[tool]\nname = "opencode"\npermission_mode = "interactive"\n')
    env["COI_USE_DUMMY"] = "1"
    container_name = _start_background_shell(coi_binary, workspace_dir, env)

    content = _read_container_file(container_name, OPENCODE_SETTINGS)
    assert content is not None, f"{OPENCODE_SETTINGS} was not written"
    settings = json.loads(content)
    assert settings.get("permission") == {"*": "ask"}, (
        f"interactive mode must set opencode permission to ask: {settings}"
    )


def test_codex_interactive_launch_flags(coi_binary, cleanup_containers, workspace_dir):
    """
    Under interactive mode codex is launched with `-s workspace-write -a
    on-request`, not the bypass flag.

    Flow:
    1. Write a fake codex script into the workspace that records its argv
    2. Configure tool=codex, permission_mode=interactive, `[tool] binary` = the
       script (COI_USE_DUMMY is not set: it would replace the binary)
    3. Start `coi shell --background`
    4. Wait for the marker file; assert the argv
    """
    script = Path(workspace_dir) / "fake-codex.sh"
    script.write_text(FAKE_CODEX)
    script.chmod(0o755)
    marker = Path(workspace_dir) / MARKER

    env = write_trusted_coi_config(
        '[tool]\nname = "codex"\nbinary = "/workspace/fake-codex.sh"\n'
        'permission_mode = "interactive"\n'
    )
    env.pop("COI_USE_DUMMY", None)
    _start_background_shell(coi_binary, workspace_dir, env)

    # The tool starts inside tmux shortly after the container is ready.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(1)
    assert marker.exists(), "the configured codex binary was not launched"

    args = marker.read_text().split("\n")
    argv = " ".join(args)
    assert "-s workspace-write -a on-request" in argv, (
        f"interactive mode must launch codex with -s workspace-write -a on-request: {args}"
    )
    assert "--dangerously-bypass-approvals-and-sandbox" not in args, (
        f"interactive mode must not pass the bypass flag: {args}"
    )
