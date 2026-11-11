"""
THROWAWAY: COI_TIMING_DEBUG before/after measurement for the names-only
instance listing PR. Removed before the PR is marked ready.

Builds the base commit, fills the host with running instances, then times
`coi run true` (restricted network) with the base and head binaries,
alternating. Prints a table to the job log and the step summary.
"""

import json
import os
import shutil
import statistics
import subprocess

BASE_SHA = "b0bf821833d977b08361fdc40084f87fd8b0948a"
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


def _measure(binary, workspace_dir, tmp_path, tag, i):
    json_path = tmp_path / f"{tag}-{i}.json"
    env = os.environ.copy()
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


def test_measure_list_perf(coi_binary, cleanup_containers, workspace_dir, tmp_path, capsys):
    """Print base vs head COI_TIMING_DEBUG phase timings on a full host."""
    config_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "config.toml"), "w") as f:
        f.write('[network]\nmode = "restricted"\n')

    base = _build_base(tmp_path)
    names = []
    try:
        names = _fill()
        count = len(_sh(["incus", "list", "--format=csv", "--columns=n"]).stdout.split())
        # Warm-up both binaries (image, caches) before timing.
        _measure(base, workspace_dir, tmp_path, "warm-base", 0)
        _measure(coi_binary, workspace_dir, tmp_path, "warm-head", 0)
        res = {"base": [], "head": []}
        for i in range(RUNS):
            res["base"].append(_measure(base, workspace_dir, tmp_path, "base", i))
            res["head"].append(_measure(coi_binary, workspace_dir, tmp_path, "head", i))
    finally:
        for i in range(0, len(names), 25):
            _sh(["incus", "delete", "--force", *names[i : i + 25]], check=False)

    keys = ["validate-env", "apply-network", "incus list", "incus query state", "total"]
    lines = [
        f"### coi run COI_TIMING_DEBUG, {count} instances, {RUNS} runs, median [min-max] ms",
        "",
        "| span | base " + BASE_SHA[:7] + " | head |",
        "|---|---|---|",
    ]
    for k in keys:
        b = [r[k] for r in res["base"] if k in r]
        h = [r[k] for r in res["head"] if k in r]
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
