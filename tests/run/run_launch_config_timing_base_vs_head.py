"""
Temporary CI benchmark for coi run - launch config calls, master vs this branch.

Tests that:
1. A master build and this build both run a restricted ephemeral launch with limits
2. Prints COI_TIMING_DEBUG numbers (total, config-call count and time) for both
"""

import json
import os
import re
import shutil
import statistics
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNS = 5
CONFIG_CALL = re.compile(r"(^|\s)(init|config set|config device (set|override))\s")

CONFIG_TOML = """
[network]
mode = "restricted"

[limits.cpu]
count = "2"

[limits.memory]
limit = "2GiB"
enforce = "soft"
swap = "false"
"""


def _build_master(dest):
    subprocess.run(
        ["git", "fetch", "--depth=1", "origin", "master"], cwd=REPO, check=True, timeout=120
    )
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(dest), "FETCH_HEAD"],
        cwd=REPO,
        check=True,
        timeout=60,
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=dest, capture_output=True, text=True, check=True
    ).stdout.strip()
    for rel in ("internal/image/embedded/dummy", "internal/config/embedded/default_config.toml"):
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, dest / rel)
    subprocess.run(
        ["go", "build", "-o", str(dest / "coi"), "./cmd/coi"], cwd=dest, check=True, timeout=600
    )
    return str(dest / "coi"), sha


def _launch(binary, workspace_dir, json_path):
    env = os.environ.copy()
    env["COI_TIMING_DEBUG_JSON"] = str(json_path)
    result = subprocess.run(
        [binary, "run", "--workspace", workspace_dir, "true"],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=workspace_dir,
        env=env,
    )
    assert result.returncode == 0, f"{binary} run failed: {result.stderr}"
    data = json.loads(json_path.read_text())
    calls = [
        r for r in data["records"] if r["category"] == "incus" and CONFIG_CALL.search(r["label"])
    ]
    return {
        "total": data["total_ms"],
        "count": len(calls),
        "config_ms": sum(r["duration_ms"] for r in calls),
        "calls": [f"{r['duration_ms']:8.1f} ms  {r['label'][:110]}" for r in calls],
    }


def _summary(name, runs):
    def med(key):
        return statistics.median(r[key] for r in runs)

    def rng(key):
        return f"{min(r[key] for r in runs):.0f}-{max(r[key] for r in runs):.0f}"

    return (
        f"{name}: total median {med('total'):.0f} ms ({rng('total')}), "
        f"config calls {runs[0]['count']}, config time median {med('config_ms'):.0f} ms "
        f"({rng('config_ms')})"
    )


def test_launch_config_timing_base_vs_head(
    coi_binary, workspace_dir, cleanup_containers, tmp_path, capsys
):
    """Measure the launch config calls of master and this build, alternating."""
    (Path(workspace_dir) / ".coi").mkdir(exist_ok=True)
    (Path(workspace_dir) / ".coi" / "config.toml").write_text(CONFIG_TOML)

    base_binary, base_sha = _build_master(tmp_path / "base")
    sides = {"base": base_binary, "head": coi_binary}
    results = {"base": [], "head": []}

    for i in range(RUNS + 1):
        for name, binary in sides.items():
            measured = _launch(binary, workspace_dir, tmp_path / f"{name}-{i}.json")
            if i > 0:
                results[name].append(measured)

    with capsys.disabled():
        print(f"\n=== launch config timing (base master {base_sha}, {RUNS} runs + 1 warm-up) ===")
        for name in ("base", "head"):
            print(_summary(name, results[name]))
            print(f"{name} config calls (first measured run):")
            print("\n".join(results[name][0]["calls"]))
