"""
THROWAWAY: COI_TIMING_DEBUG before/after measurement for the names-only
instance listing PR. Removed before the PR is marked ready.

Builds the base commit, fills the host with running instances, then times
`coi run true` (restricted network) with the base and head binaries,
alternating, once unnamed and once with a [container] session_name (only a
named launch lists the workspace sessions in validate-env). Prints a table to
the job log and the step summary.
"""

import json
import os
import shutil
import statistics
import subprocess

from support.helpers import write_trusted_coi_config

BASE_SHA = "a3bcd3d0ba87e2101793778f09239fbfd7d67975"
FILL = int(os.environ.get("COI_PERF_FILL", "185"))
RUNS = int(os.environ.get("COI_PERF_RUNS", "5"))
PREFIX = "perffill-"


def _sh(args, timeout=600, check=True, cwd=None, env=None):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
    if check and r.returncode != 0:
        raise AssertionError(f"{args[:4]} failed: {r.stdout[-1500:]} {r.stderr[-1500:]}")
    return r


def _build_base(tmp_path):
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    wt = tmp_path / "base"
    _sh(["git", "fetch", "--depth=1", "origin", BASE_SHA], cwd=repo)
    _sh(["git", "worktree", "add", "--detach", str(wt), BASE_SHA], cwd=repo)
    (wt / "internal/image/embedded").mkdir(parents=True, exist_ok=True)
    (wt / "internal/config/embedded").mkdir(parents=True, exist_ok=True)
    shutil.copy(wt / "testdata/dummy/dummy", wt / "internal/image/embedded/dummy")
    cfg = (wt / "profiles/default/config.toml").read_text()
    (wt / "internal/config/embedded/default_config.toml").write_text(
        cfg.replace('swap = "true"', 'swap = ""')
    )
    _sh(["go", "build", "-o", str(wt / "coi"), "./cmd/coi"], cwd=str(wt), timeout=900)
    return str(wt / "coi")


def _fill():
    src = PREFIX + "000"
    for _ in range(3):
        if _sh(["incus", "init", "images:alpine/3.22", src], check=False).returncode == 0:
            break
    else:
        raise AssertionError("could not create the alpine filler")
    names = [f"{PREFIX}{i:03d}" for i in range(1, FILL)]
    for n in names:
        _sh(["incus", "copy", src, n])
    names.insert(0, src)
    for i in range(0, len(names), 25):
        _sh(["incus", "start", *names[i : i + 25]])
    return names


def _measure(binary, workspace_dir, tmp_path, tag, i, base_env):
    json_path = tmp_path / f"{tag}-{i}.json"
    env = dict(base_env)
    env["COI_TIMING_DEBUG_JSON"] = str(json_path)
    env.pop("COI_TIMING_DEBUG", None)
    _sh([binary, "run", "--workspace", workspace_dir, "true"], timeout=600, env=env)
    data = json.loads(json_path.read_text())
    out = {"total": data["total_ms"]}
    for r in data["records"]:
        if r["category"] == "phase" and r["label"] in ("validate-env", "apply-network"):
            out[r["label"]] = out.get(r["label"], 0) + r["duration_ms"]
        if r["category"] == "incus" and r["label"].startswith("list"):
            out["incus list"] = out.get("incus list", 0) + r["duration_ms"]
        if r["category"] == "incus" and "query /1.0/instances/" in r["label"]:
            out["incus query state"] = out.get("incus query state", 0) + r["duration_ms"]
    return out


def _fmt(vals):
    if not vals:
        return "-"
    return f"{statistics.median(vals):.0f} [{min(vals):.0f}-{max(vals):.0f}]"


SCENARIOS = {
    "unnamed": '[network]\nmode = "restricted"\n',
    "named": '[container]\nsession_name = "perfnamed"\n\n[network]\nmode = "restricted"\n',
}


def test_measure_list_perf(coi_binary, cleanup_containers, workspace_dir, tmp_path, capsys):
    """Print base vs head COI_TIMING_DEBUG phase timings on a full host."""
    envs = {k: write_trusted_coi_config(v) for k, v in SCENARIOS.items()}
    base = _build_base(tmp_path)
    names = []
    res = {}
    try:
        names = _fill()
        count = len(_sh(["incus", "list", "--format=csv", "--columns=n"]).stdout.split())
        for sc, env in envs.items():
            # Warm-up both binaries (image, caches) before timing.
            _measure(base, workspace_dir, tmp_path, f"warm-base-{sc}", 0, env)
            _measure(coi_binary, workspace_dir, tmp_path, f"warm-head-{sc}", 0, env)
            res[sc] = {"base": [], "head": []}
            for i in range(RUNS):
                res[sc]["base"].append(
                    _measure(base, workspace_dir, tmp_path, f"base-{sc}", i, env)
                )
                res[sc]["head"].append(
                    _measure(coi_binary, workspace_dir, tmp_path, f"head-{sc}", i, env)
                )
    finally:
        for i in range(0, len(names), 25):
            _sh(["incus", "delete", "--force", *names[i : i + 25]], check=False)

    keys = ["validate-env", "apply-network", "incus list", "incus query state", "total"]
    lines = []
    for sc, r in res.items():
        lines += [
            f"### coi run ({sc}) COI_TIMING_DEBUG, {count} instances, {RUNS} runs, median [min-max] ms",
            "",
            "| span | base " + BASE_SHA[:7] + " | head |",
            "|---|---|---|",
        ]
        for k in keys:
            b = [x[k] for x in r["base"] if k in x]
            h = [x[k] for x in r["head"] if k in x]
            lines.append(f"| {k} | {_fmt(b)} | {_fmt(h)} |")
        lines.append("")
    lines.append("raw: " + json.dumps(res))
    text = "\n".join(lines)
    with capsys.disabled():
        print("\nCOI_PERF_RESULT_BEGIN\n" + text + "\nCOI_PERF_RESULT_END\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(text + "\n")
