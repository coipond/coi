"""
Test that [tool] context_json_file injects a custom JSON verbatim (#705).

context_json_file reads an arbitrary HOST file and writes it into the container,
so it is honored only from TRUSTED scope (COI_CONFIG / ~/.coi/config.toml), never
from an untrusted project .coi/config.toml. This test sets it via COI_CONFIG and
verifies the container's ~/SANDBOX_CONTEXT.json is the custom file's content
(not the generated JSON).
"""

import json
import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    write_trusted_coi_config,
)

CUSTOM_JSON = json.dumps(
    {"schema_version": 99, "custom_marker": "Coi-CUSTOM-JSON-TEST", "note": "injected verbatim"}
)


def test_context_json_custom_file_injected_verbatim(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    container_name = calculate_container_name(workspace_dir, 1)

    # The custom JSON the user wants injected.
    custom_json_path = tmp_path / "my-context.json"
    custom_json_path.write_text(CUSTOM_JSON)

    # Point [tool] context_json_file at it from TRUSTED scope (COI_CONFIG).
    env = write_trusted_coi_config(f'[tool]\ncontext_json_file = "{custom_json_path}"\n')
    env["COI_USE_DUMMY"] = "1"

    # Credentials for setup.
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    claude_dir = fake_home / ".claude"
    claude_dir.mkdir()
    (claude_dir / ".credentials.json").write_text('{"token": "test"}')
    env["HOME"] = str(fake_home)

    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)

    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(2)

    result = subprocess.run(
        [
            "sg",
            "incus-admin",
            "-c",
            f"incus exec {container_name} -- cat /home/code/SANDBOX_CONTEXT.json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    exists = result.returncode == 0
    content = result.stdout

    # Cleanup
    child.send("sudo poweroff")
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
    time.sleep(5)
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )

    assert exists, "~/SANDBOX_CONTEXT.json should exist when context_json_file is set"
    assert "Coi-CUSTOM-JSON-TEST" in content, (
        f"custom JSON should be injected verbatim, got:\n{content[:500]}"
    )
    data = json.loads(content)
    assert data.get("schema_version") == 99, (
        f"schema_version should be the custom 99 (not the generated 1), got {data.get('schema_version')!r}"
    )
    # Generated JSON would carry the container name; the custom one must not.
    assert container_name not in content, (
        "custom JSON should replace the generated content (container name leaked through)"
    )
