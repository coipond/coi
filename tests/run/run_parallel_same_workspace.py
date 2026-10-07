"""
Parallel launches of the same workspace each get their own container.

A launch picks its slot by listing the workspace's containers and taking the
first free one, then creates coi-<hash>-<slot>. Before the per-workspace launch
lock (session.AcquireLaunchLock), concurrent launches could pick the same slot:
one failed with "already exists" / "already running", and an ephemeral run
could even delete another's container mid-setup ("Removing existing
container..."). Now slot selection is serialised until each launch's container
is up, so every concurrent launch succeeds in a distinct container.
"""

import subprocess
from concurrent.futures import ThreadPoolExecutor

from support.helpers import write_trusted_coi_config

PARALLEL = 3


def _run_parallel(coi_binary, workspace_dir, env=None):
    def one(_):
        return subprocess.run(
            # Stay up long enough that all launches overlap: a launch that
            # already finished frees its slot, which a later one may then
            # legitimately reuse (a stopped persistent container) or re-take.
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                "hostname; sleep 20",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )

    with ThreadPoolExecutor(max_workers=PARALLEL) as pool:
        return list(pool.map(one, range(PARALLEL)))


def _assert_all_ok_and_distinct(results):
    for r in results:
        assert r.returncode == 0, (
            f"a parallel launch failed:\nstdout: {r.stdout}\nstderr: {r.stderr}"
        )
    names = [r.stdout.strip().splitlines()[-1] for r in results]
    assert len(set(names)) == PARALLEL, (
        f"parallel launches must use distinct containers, got {names}"
    )
    for r in results:
        assert "Removing existing container" not in r.stderr, (
            f"a launch removed a container another launch was setting up:\n{r.stderr}"
        )


def test_parallel_ephemeral_runs_same_workspace(coi_binary, cleanup_containers, workspace_dir):
    _assert_all_ok_and_distinct(_run_parallel(coi_binary, workspace_dir))


def test_parallel_persistent_runs_same_workspace(coi_binary, cleanup_containers, workspace_dir):
    env = write_trusted_coi_config("[container]\npersistent = true\n")
    _assert_all_ok_and_distinct(_run_parallel(coi_binary, workspace_dir, env=env))
