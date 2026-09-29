"""
Codex host-config seeding and auto-context into ~/.codex/AGENTS.md (#698).

Verifies that with [tool] name = "codex":
1. Host ~/.codex/{auth.json, config.toml, AGENTS.md} are seeded into the
   container.
2. config.toml arrives BYTE-IDENTICAL — codex config is TOML, and coi's
   sandbox-settings merge is JSON-only, so codex deliberately has no
   sandbox_settings_file and the host file must never be rewritten.
3. The Coi sandbox context block is injected into ~/.codex/AGENTS.md
   (codex's native global-instructions file), preserving the host content,
   exactly once.

Runs with COI_USE_DUMMY=1 so the image does not need the codex binary
installed (codex is opt-in at image build).
"""

import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    spawn_coi,
    wait_for_container_ready,
)

CONFIG_TOML = (
    "# user config — must survive seeding byte-for-byte\n"
    'model = "gpt-5-codex"\n'
    "\n"
    "[sandbox_workspace_write]\n"
    "network_access = true\n"
)
AUTH_JSON = '{"tokens": {"access_token": "fake-token"}}'
AGENTS_MD = "# My global codex instructions\nUSER-CODEX-AGENTS-CONTENT\n"


def _read_container_file(container_name, path):
    result = subprocess.run(
        ["sg", "incus-admin", "-c", f"incus exec {container_name} -- cat {path}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode == 0, result.stdout


def test_codex_config_seeded_verbatim_and_agents_md_context(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    container_name = calculate_container_name(workspace_dir, 1)

    # Select codex via project config.
    config_dir = f"{workspace_dir}/.coi"
    subprocess.run(["mkdir", "-p", config_dir], check=True)
    with open(f"{config_dir}/config.toml", "w") as f:
        f.write('[tool]\nname = "codex"\n')

    # Fake host home with a populated ~/.codex.
    fake_home = tmp_path / "fake_home"
    codex_dir = fake_home / ".codex"
    codex_dir.mkdir(parents=True)
    (codex_dir / "config.toml").write_text(CONFIG_TOML)
    (codex_dir / "auth.json").write_text(AUTH_JSON)
    (codex_dir / "AGENTS.md").write_text(AGENTS_MD)

    env = {"COI_USE_DUMMY": "1", "HOME": str(fake_home)}

    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    time.sleep(5)

    toml_ok, toml_content = _read_container_file(container_name, "/home/code/.codex/config.toml")
    auth_ok, auth_content = _read_container_file(container_name, "/home/code/.codex/auth.json")
    agents_ok, agents_content = _read_container_file(container_name, "/home/code/.codex/AGENTS.md")
    state_exists, _ = _read_container_file(container_name, "/home/code/.codex.json")

    # Cleanup
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    try:
        child.expect(EOF, timeout=60)
    except TIMEOUT:
        pass
    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)
    time.sleep(2)
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )

    # Seeding: all three host files present.
    assert auth_ok, "~/.codex/auth.json should be seeded from the host"
    assert auth_content == AUTH_JSON, f"auth.json changed during seeding:\n{auth_content!r}"

    assert toml_ok, "~/.codex/config.toml should be seeded from the host"
    assert toml_content == CONFIG_TOML, (
        "config.toml must be seeded BYTE-IDENTICAL (TOML must never pass through "
        f"the JSON settings merge):\n got: {toml_content!r}\nwant: {CONFIG_TOML!r}"
    )

    # Auto-context: host AGENTS.md content preserved + exactly one Coi block.
    assert agents_ok, "~/.codex/AGENTS.md should exist (seeded + auto-context)"
    assert agents_content.count("USER-CODEX-AGENTS-CONTENT") == 1, (
        f"host AGENTS.md content must be preserved exactly once:\n{agents_content[:500]}"
    )
    assert agents_content.count("# COI Sandbox Environment") == 1, (
        f"AGENTS.md should contain exactly one Coi sandbox block:\n{agents_content[:500]}"
    )

    # No sibling state file may be synthesized (codex has no ~/.codex.json).
    assert not state_exists, "a ~/.codex.json state file was synthesized; codex must not have one"
