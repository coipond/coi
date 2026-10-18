"""
Test that coi shell --resume with [tool] name = "opencode" resumes the same
opencode session (`--session ses_...`), found in opencode's SQLite DB in the
workspace, instead of `--continue`.

Flow:
1. Write .coi/config.toml with [tool] name = "opencode"
2. Start coi shell with the real opencode binary (creates the DB)
3. Import a session with a known ses_ id into the workspace's DB
4. Exit opencode, poweroff, wait for the container to go
5. Run coi shell --resume
6. Verify the relaunched opencode runs with --session <that id>
"""

import json
import os
import subprocess
import time

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    spawn_coi,
    wait_for_container_ready,
    wait_for_specific_container_deletion,
    wait_for_text_on_screen,
)

SESSION_ID = "ses_0c01resume0aBcDeFgHiJkLmNo"

OPENCODE_ENV = [
    "--env",
    "HOME=/home/code",
    "--env",
    "XDG_DATA_HOME=/workspace/.local/share",
    "--env",
    "XDG_STATE_HOME=/workspace/.local/state",
]


def _exec_as_code(container_name, cmd, timeout=60):
    return subprocess.run(
        [
            "incus",
            "exec",
            container_name,
            "--user",
            "1000",
            "--group",
            "1000",
            "--cwd",
            "/workspace",
            *OPENCODE_ENV,
            "--",
            *cmd,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _shutdown(child, coi_binary, container_name):
    child.send("\x03")
    time.sleep(1)
    child.send("\x03")
    time.sleep(2)
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
    if not wait_for_specific_container_deletion(container_name, timeout=60):
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )


def test_opencode_resume_lands_in_same_session(coi_binary, cleanup_containers, workspace_dir):
    config_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "config.toml"), "w") as f:
        f.write('[tool]\nname = "opencode"\n')

    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: start opencode and give it a session ===

    child = spawn_coi(coi_binary, ["shell"], cwd=workspace_dir, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_text_on_screen(child, "OpenCode", timeout=60)

    now = int(time.time() * 1000)
    export = {
        "info": {
            "id": SESSION_ID,
            "slug": "coi-resume-test",
            "projectID": "global",
            "directory": "/workspace",
            "title": "coi resume test",
            "version": "1.19.3",
            "time": {"created": now, "updated": now},
        },
        "messages": [],
    }
    with open(os.path.join(workspace_dir, "coi-resume-session.json"), "w") as f:
        json.dump(export, f)

    imported = _exec_as_code(
        container_name, ["opencode", "import", "/workspace/coi-resume-session.json"]
    )
    listed = _exec_as_code(
        container_name,
        ["opencode", "db", "SELECT id, directory FROM session", "--format", "json"],
    )

    _shutdown(child, coi_binary, container_name)

    assert SESSION_ID in listed.stdout, (
        f"opencode import should create the session in the workspace DB.\n"
        f"import: {imported.stdout}{imported.stderr}\ndb: {listed.stdout}{listed.stderr}"
    )

    # === Phase 2: resume ===

    child2 = spawn_coi(coi_binary, ["shell", "--resume"], cwd=workspace_dir, timeout=120)
    wait_for_container_ready(child2, timeout=60)
    wait_for_text_on_screen(child2, "OpenCode", timeout=60)

    ps = subprocess.run(
        ["incus", "exec", container_name, "--", "ps", "-eo", "args"],
        capture_output=True,
        text=True,
        timeout=10,
    )

    _shutdown(child2, coi_binary, container_name)

    launched = [
        line for line in ps.stdout.splitlines() if "opencode" in line and "--session" in line
    ]
    assert any(f"--session {SESSION_ID}" in line for line in launched), (
        f"coi shell --resume should launch opencode with --session {SESSION_ID}. Processes:\n{ps.stdout}"
    )
