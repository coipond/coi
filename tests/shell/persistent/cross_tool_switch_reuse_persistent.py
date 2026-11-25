"""
#708 end-to-end: create a persistent box with ONE tool, then re-enter it with
ANOTHER tool — the box is reused and the new tool's config is seeded while the
original tool's config is left intact.

This is the full claude→codex switch. It needs no two-tool image: the base image
ships the dummy stub at /usr/local/bin/dummy and COI_USE_DUMMY rewrites any tool's
LAUNCH to it, while coi still seeds the configured tool's REAL config dir
(~/.claude for name=claude, ~/.codex for name=codex) from a fake host home. So we
exercise coi's actual per-tool seeding across a reuse without installing real
agents.

The tool is selected via a per-phase trusted $COI_CONFIG (a temp file OUTSIDE the
workspace) rather than a workspace .coi/config.toml — coi makes the workspace
config immutable during the first session, so it can't be rewritten between
phases.

Flow:
  1. name=claude, persistent → create box; ~/.claude seeded, ~/.codex absent.
  2. stop the box.
  3. $COI_CONFIG now selects name=codex; fresh `coi shell` (no --resume) reuses
     the SAME box.
  4. ~/.codex is now seeded (the reuse-seeding branch) AND ~/.claude is untouched.
"""

import subprocess
import time

from support.helpers import (
    calculate_container_name,
    container_cat,
    container_path_exists,
    spawn_coi,
    wait_for_container_ready,
    write_trusted_coi_config,
)

CLAUDE_CRED = '{"marker": "claude-cred-708"}'
CODEX_AUTH = '{"tokens": {"access_token": "codex-auth-708"}}'

CLAUDE_CRED_PATH = "/home/code/.claude/.credentials.json"
CODEX_AUTH_PATH = "/home/code/.codex/auth.json"


def _incus(argv, timeout=30):
    return subprocess.run(
        ["sg", "incus-admin", "-c", "incus " + argv],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _env_for(tool_name, fake_home):
    # Trusted $COI_CONFIG (temp file outside the workspace) selects the tool +
    # persistence; freely rewritable between phases.
    env = write_trusted_coi_config(
        f'[tool]\nname = "{tool_name}"\n[container]\npersistent = true\n'
    )
    env["HOME"] = str(fake_home)
    env["COI_USE_DUMMY"] = "1"
    return env


def _close(child):
    try:
        child.send("exit")
        time.sleep(0.3)
        child.send("\x0d")
        time.sleep(1)
    except Exception:
        pass
    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)


def test_switch_tool_on_reused_container(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    container_name = calculate_container_name(workspace_dir, 1)

    # Fake host home holding BOTH tools' configs to seed from.
    fake_home = tmp_path / "fake_home"
    (fake_home / ".claude").mkdir(parents=True)
    (fake_home / ".claude" / ".credentials.json").write_text(CLAUDE_CRED)
    (fake_home / ".codex").mkdir(parents=True)
    (fake_home / ".codex" / "auth.json").write_text(CODEX_AUTH)
    (fake_home / ".codex" / "config.toml").write_text('model = "gpt-5-codex"\n')
    (fake_home / ".codex" / "AGENTS.md").write_text("# codex\n")

    claude_seeded = codex_absent_phase1 = False
    codex_seeded_on_reuse = claude_still_present = False
    try:
        # === Phase 1: create the box with claude ===
        child = spawn_coi(
            coi_binary, ["shell"], cwd=workspace_dir, env=_env_for("claude", fake_home), timeout=120
        )
        wait_for_container_ready(child, timeout=60)
        time.sleep(5)
        ok, content = container_cat(coi_binary, container_name, CLAUDE_CRED_PATH)
        claude_seeded = ok and content.strip() == CLAUDE_CRED
        # The base image pre-creates ~/.codex empty, so check the SEEDED marker
        # file is absent (codex wasn't the active tool), not the dir.
        codex_absent_phase1 = not container_path_exists(coi_binary, container_name, CODEX_AUTH_PATH)

        _close(child)
        time.sleep(2)
        _incus(f"stop {container_name} --force", timeout=60)
        time.sleep(2)

        # === Phase 2: re-enter the SAME box with codex ===
        child2 = spawn_coi(
            coi_binary, ["shell"], cwd=workspace_dir, env=_env_for("codex", fake_home), timeout=120
        )
        wait_for_container_ready(child2, timeout=60)
        time.sleep(5)
        ok_codex, codex_content = container_cat(coi_binary, container_name, CODEX_AUTH_PATH)
        codex_seeded_on_reuse = ok_codex and codex_content.strip() == CODEX_AUTH
        ok_claude, claude_content = container_cat(coi_binary, container_name, CLAUDE_CRED_PATH)
        claude_still_present = ok_claude and claude_content.strip() == CLAUDE_CRED
        _close(child2)
    finally:
        time.sleep(2)
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )

    assert claude_seeded, "phase 1: ~/.claude/.credentials.json should be seeded for name=claude"
    assert codex_absent_phase1, (
        "phase 1: ~/.codex/auth.json must NOT be seeded yet (codex wasn't the active tool)"
    )
    assert codex_seeded_on_reuse, (
        "phase 2: switching to codex on the reused box must seed ~/.codex/auth.json (#708)"
    )
    assert claude_still_present, (
        "phase 2: seeding codex must not disturb the original tool's config (~/.claude)"
    )
