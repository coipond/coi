"""
`coi run --prompt` is rejected when the tool's permission mode is interactive.

Headless prompt mode has no terminal to answer permission requests, so an
interactive permission_mode would block every tool use. coi refuses it with a
usage error (exit 2) before any container is created (#701).
"""

import subprocess

from support.helpers import write_trusted_coi_config


def test_prompt_with_interactive_permission_mode_rejected(coi_binary, workspace_dir):
    env = write_trusted_coi_config('[tool]\npermission_mode = "interactive"\n')
    r = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--prompt", "do it"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    out = r.stdout + r.stderr
    assert r.returncode == 2, f"want exit 2, got {r.returncode}: {out}"
    assert 'needs [tool] permission_mode = "bypass"' in out, out
