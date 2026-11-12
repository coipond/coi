"""
E2E test: `coi health` probe containers honor the kernel-surface policy.

The four runtime-isolation probes (connectivity, network restriction, secret
masking, host-credential isolation) launch short-lived real containers. Under
[security] reduce_kernel_surface those probes must NOT silently boot with the
full docker/nesting surface — the exact class of widening the policy exists
to prevent.

The probes only live a few seconds, so the test runs `coi health` in the
background and polls `incus list` fast, snapshotting each probe container's
expanded config the moment it appears.
"""

import json
import os
import subprocess
import tempfile
import time

import pytest

PROBE_PREFIXES = (
    "coi-health-check-",
    "coi-restriction-check-",
    "coi-secret-check-",
    "coi-hostcred-check-",
)


def _write_hardened_config():
    fd, path = tempfile.mkstemp(suffix=".toml", prefix="coi-hardened-")
    with os.fdopen(fd, "w") as f:
        f.write("[security]\nreduce_kernel_surface = true\n")
    return {**os.environ, "COI_CONFIG": path}


def _probe_started_ns(name):
    """The UnixNano timestamp coi embeds in a probe name, or None."""
    for prefix in PROBE_PREFIXES:
        if name.startswith(prefix):
            suffix = name[len(prefix) :]
            return int(suffix) if suffix.isdigit() else None
    return None


def _list_running_probe_containers(since_ns):
    """Probe containers currently RUNNING that were named at or after since_ns.
    Older probes were left by earlier tests, not this health run. The
    kernel-surface policy is applied at init, strictly BEFORE the first start —
    so reading the config of a not-yet-started probe races the setup and can
    observe the pre-policy state. A RUNNING probe's config is authoritative."""
    result = subprocess.run(
        ["incus", "list", "--format", "csv", "-c", "ns", "coi-"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    names = []
    for row in result.stdout.strip().splitlines():
        parts = row.strip().split(",")
        if len(parts) < 2 or parts[1].upper() != "RUNNING":
            continue
        started_ns = _probe_started_ns(parts[0])
        if started_ns is not None and started_ns >= since_ns:
            names.append(parts[0])
    return names


def _expanded_get(name, key):
    result = subprocess.run(
        ["incus", "config", "get", "--expanded", name, key],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.returncode, result.stdout.strip()


def test_health_probes_honor_reduce_kernel_surface(coi_binary, cleanup_containers):
    """While a hardened `coi health` runs, every probe container observed must
    carry the hardened policy: nesting off and the syscall deny list set."""
    env = _write_hardened_config()

    started_ns = time.time_ns()
    proc = subprocess.Popen(
        [coi_binary, "health", "--format", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    observed = {}  # probe name -> (nesting, deny)
    samples = []  # rolling `incus list` snapshots for failure diagnostics
    try:
        # Poll while the health run is alive; each probe lives seconds. No
        # sleep — the incus list roundtrip (~50-100ms) is the throttle.
        while proc.poll() is None:
            names = _list_running_probe_containers(started_ns)
            if names and (not samples or samples[-1][1] != names):
                samples.append((time.time(), names))
            for name in names:
                if name in observed:
                    continue
                rc_n, nesting = _expanded_get(name, "security.nesting")
                rc_d, deny = _expanded_get(name, "security.syscalls.deny")
                # The container may vanish between list and get; only record
                # complete reads of a container that was RUNNING at list time.
                if rc_n == 0 and rc_d == 0:
                    observed[name] = (nesting, deny)
        stdout, stderr = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()

    # The health run itself must have completed and produced JSON — hardened
    # probes must still boot and function (the deny list breaks nothing).
    assert proc.returncode in (0, 1, 2), f"coi health crashed: rc={proc.returncode}\n{stderr}"
    data = json.loads(stdout)
    assert "checks" in data

    # When we DID catch a probe running, its config is authoritative: assert
    # the policy took effect. When we didn't, the probe either failed to boot
    # (nested-idmap-constrained runners) or lived too briefly to sample — both
    # are environment limitations, not a policy regression, so skip rather than
    # flake. The deterministic guarantee that the policy is threaded to the
    # launch lives in the Go test TestProbesThreadHardeningPolicyToLaunch; this
    # E2E is the opportunistic real-boot confirmation on top of it.
    if not observed:
        probe_results = {
            k: {"status": v.get("status"), "message": (v.get("message") or "")[:120]}
            for k, v in data["checks"].items()
            if k
            in (
                "container_connectivity",
                "network_restriction",
                "secret_masking",
                "host_credential_isolation",
            )
        }
        pytest.skip(
            "no RUNNING probe container was observable while coi health ran "
            "(probes failed to boot or were too short-lived to sample). "
            "Policy threading is covered deterministically by the Go test.\n"
            f"probe check results: {json.dumps(probe_results, indent=2)}\n"
            f"running-probe samples: {samples}"
        )

    for name, (nesting, deny) in observed.items():
        assert nesting.lower() not in ("true", "1", "yes", "on"), (
            f"probe {name} booted with security.nesting={nesting!r} despite "
            "reduce_kernel_surface — probes must honor the kernel-surface policy"
        )
        assert "bpf" in deny.split(), f"probe {name} is missing the syscall deny list, got {deny!r}"
