"""
Test that network setup purges stale per-IP nft rules before applying policy.

nft rules in the `ip coi forward` chain are keyed by container IP (comment
"coi-<IP>"), and the chain is evaluated first-match-wins. Incus DHCP recycles
leases, so a new container can reuse a prior container's IP. If the prior
container's rules were orphaned (unclean teardown), a leftover blanket ACCEPT
sitting ahead of a restricted successor's rules would let it bypass its filter.

Reproduced deterministically with a persistent container ([container]
persistent = true in the workspace config) pinned to a fixed slot:
1. `coi run --slot 1 -- sleep` (background); once it reports network
   isolation applied, capture the container IP, then SIGINT the run. Its teardown
   removes the rules; persistent mode keeps the container (stopped).
2. Inject a uniquely fingerprinted ACCEPT rule for that IP (a TEST-NET-3
   destination a real restricted setup never produces) — an orphan stand-in.
3. `coi run --slot 1 -- sleep` again. The same persistent container
   restarts (same MAC -> same IP) and network setup re-runs. Wait for it to
   report network isolation applied (so purge + apply have completed) and, while
   the run is still live (before its teardown), assert the fingerprint rule is
   gone — i.e. setup purged coi-<IP> before re-applying the restricted policy.

Gating on the "Network isolation applied" log line (printed after
SetupForContainer returns) is what makes this meaningful: it pins the check to
*after* the second setup, and distinguishes a real purge from the injected rule
merely lingering. Inspecting while the run is live distinguishes purge from
teardown, since both remove coi-<IP> rules.
"""

import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time

import pytest

from support.helpers import calculate_container_name, container_ipv4

# RFC 5737 TEST-NET-3 — never a real resolved/allowlisted address, so a clean
# restricted setup never produces a rule referencing it.
FINGERPRINT = "203.0.113.7"
NET_APPLIED_MARKER = "Network isolation applied"


def nft_available():
    try:
        subprocess.run(
            ["sudo", "-n", "nft", "list", "ruleset"],
            capture_output=True,
            timeout=10,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def chain_text():
    result = subprocess.run(
        ["sudo", "-n", "nft", "list", "chain", "ip", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout if result.returncode == 0 else ""


def start_run(coi_binary, workspace_dir, stderr_file):
    """Start a long-lived `coi run` on slot 1 so the container stays up to inspect."""
    return subprocess.Popen(
        [
            coi_binary,
            "run",
            "--slot",
            "1",
            "--workspace",
            str(workspace_dir),
            "sleep",
            "300",
        ],
        stdout=subprocess.DEVNULL,
        stderr=stderr_file,
        text=True,
    )


def wait_for_marker(stderr_path, proc, timeout=150):
    """Poll the run's stderr file until the network-applied marker appears."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            text = pathlib.Path(stderr_path).read_text(errors="replace")
        except FileNotFoundError:
            text = ""
        if NET_APPLIED_MARKER in text:
            return True
        if proc.poll() is not None:
            return NET_APPLIED_MARKER in text
        time.sleep(1)
    return False


def stop_run(proc):
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def wait_for_stopped(name, timeout=60):
    """Wait until the container is no longer Running, force-stopping as a fallback.

    The SIGINT teardown stops the persistent container, but the stop can lag the
    coi process exit; without this, the next `coi run` can race and fail with
    'instance already running'.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["incus", "list", name, "--format=json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return  # container gone / not listable
        info = json.loads(result.stdout)
        if not info or info[0].get("status") != "Running":
            return
        time.sleep(1)
    # Fallback: force-stop so the restart in the next phase is deterministic.
    subprocess.run(["incus", "stop", name, "--force"], capture_output=True, timeout=60)


def test_setup_purges_stale_rules_for_reused_ip(coi_binary, workspace_dir, cleanup_containers):
    if not nft_available():
        pytest.skip("nft not available")

    container_name = calculate_container_name(workspace_dir, 1)
    config_dir = pathlib.Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        '[network]\nmode = "restricted"\n\n[container]\npersistent = true\n'
    )

    fd1, err1 = tempfile.mkstemp(suffix=".err")
    fd2, err2 = tempfile.mkstemp(suffix=".err")
    os.close(fd1)
    os.close(fd2)
    fh1 = open(err1, "w")  # noqa: SIM115 — must stay open for the child's stderr
    fh2 = open(err2, "w")  # noqa: SIM115

    try:
        # === Phase 1: bring the container up, capture its IP ===
        proc1 = start_run(coi_binary, workspace_dir, fh1)
        if not wait_for_marker(err1, proc1):
            stop_run(proc1)
            pytest.skip(f"network isolation not applied within timeout; stderr:\n{_read(err1)}")

        container_ip = container_ipv4(container_name)
        assert container_ip, "should resolve the container IP after first setup"
        assert FINGERPRINT not in chain_text(), "fingerprint must not pre-exist"

        # SIGINT: teardown removes the rules; persistent mode keeps the container.
        stop_run(proc1)
        # Ensure it is fully stopped before restarting in phase 3 (avoids the
        # "instance already running" race when the stop lags the process exit).
        wait_for_stopped(container_name)

        # === Phase 2: inject an orphan rule for that IP ===
        inject = subprocess.run(
            [
                "sudo",
                "-n",
                "nft",
                "add",
                "rule",
                "ip",
                "coi",
                "forward",
                "ip",
                "saddr",
                container_ip,
                "ip",
                "daddr",
                f"{FINGERPRINT}/32",
                "accept",
                "comment",
                f"coi-{container_ip}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert inject.returncode == 0, (
            f"injecting stale rule should succeed. stderr: {inject.stderr}"
        )
        assert FINGERPRINT in chain_text(), "precondition: injected stale rule must be present"

        # === Phase 3: restart the same persistent container -> setup re-runs ===
        proc2 = start_run(coi_binary, workspace_dir, fh2)
        try:
            applied = wait_for_marker(err2, proc2)
            assert applied, f"second run should re-apply network isolation; stderr:\n{_read(err2)}"

            # Confirm the persistent container actually reused the same IP — only
            # then does the second setup target (and purge) container_ip's rules.
            reused_ip = container_ipv4(container_name)
            if reused_ip != container_ip:
                pytest.skip(
                    f"persistent restart did not reuse the IP (was {container_ip}, "
                    f"got {reused_ip}); cannot exercise the purge"
                )

            # Setup has completed (purge + apply) and the run is still live (no
            # teardown). The stale rule must be gone — proving setup purged it.
            current = chain_text()
            assert FINGERPRINT not in current, (
                f"stale coi-{container_ip} rule ({FINGERPRINT}) survived restart — "
                f"DHCP-reuse inheritance was not purged by setup.\nchain:\n{current}"
            )
        finally:
            stop_run(proc2)
    finally:
        for fh in (fh1, fh2):
            try:
                fh.close()
            except OSError:
                pass
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=60,
        )
        for p in (err1, err2):
            pathlib.Path(p).unlink(missing_ok=True)


def _read(path):
    try:
        return pathlib.Path(path).read_text(errors="replace")
    except OSError:
        return ""
