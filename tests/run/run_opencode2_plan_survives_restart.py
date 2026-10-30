"""
Test for coi run - opencode2's plan files survive an ephemeral restart.

OpenCode v2's Plan agent writes its plans to ~/.opencode/plan, outside the
workspace, so they used to go with the ephemeral container. coi now mounts a
per-workspace host dir there (~/.coi/tool-data/opencode2/<hash>/plan).

Tests that:
1. A plan written in one ephemeral container is there in the next one
2. ~/.opencode and ~/.opencode/plan belong to the code user
3. The plan lands in the host tool-data dir, not in the workspace
4. A project's own <workspace>/.opencode/plan is left in place (not moved
   into the mount)
"""

import os
import shutil
import subprocess
from pathlib import Path

from support.helpers import tool_data_dir

WRITE = (
    "stat -c 'owner %U %n' ~/.opencode ~/.opencode/plan; "
    "ls ~/.opencode/plan; "
    "echo step-1 > ~/.opencode/plan/coi-test-plan.md"
)
READ = "cat ~/.opencode/plan/coi-test-plan.md"


def _run(coi_binary, workspace_dir, cfg, command):
    env = os.environ.copy()
    env["COI_CONFIG"] = str(cfg)
    env.pop("COI_USE_DUMMY", None)
    return subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=240,
        stdin=subprocess.DEVNULL,
        env=env,
    )


def test_opencode2_plan_survives_ephemeral_restart(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    own_plan = Path(workspace_dir) / ".opencode" / "plan" / "project-notes.md"
    own_plan.parent.mkdir(parents=True)
    own_plan.write_text("project file\n")

    cfg = tmp_path / "cfg.toml"
    cfg.write_text('[tool]\nname = "opencode2"\n')
    plan_dir = tool_data_dir(workspace_dir, "opencode2", "plan")
    try:
        # === Phase 1: write a plan in the first ephemeral container ===
        first = _run(coi_binary, workspace_dir, cfg, WRITE)
        output = first.stdout + first.stderr
        assert first.returncode == 0, f"first run failed:\n{output}"
        lines = first.stdout.splitlines()
        for path in ("/home/code/.opencode", "/home/code/.opencode/plan"):
            assert f"owner code {path}" in lines, f"{path} should be owned by code:\n{output}"
        assert "project-notes.md" not in lines, (
            f"the workspace's own .opencode/plan must not be moved into the mount:\n{output}"
        )

        assert (plan_dir / "coi-test-plan.md").read_text().strip() == "step-1", output
        assert own_plan.read_text() == "project file\n", "the workspace's own plan file changed"
        assert not (Path(workspace_dir) / ".opencode" / "plan" / "coi-test-plan.md").exists()

        # === Phase 2: a new ephemeral container sees the plan ===
        second = _run(coi_binary, workspace_dir, cfg, READ)
        assert second.returncode == 0, f"second run failed:\n{second.stdout}{second.stderr}"
        assert second.stdout.strip() == "step-1", (
            f"the plan should survive the restart:\n{second.stdout}{second.stderr}"
        )
    finally:
        shutil.rmtree(plan_dir.parent, ignore_errors=True)
