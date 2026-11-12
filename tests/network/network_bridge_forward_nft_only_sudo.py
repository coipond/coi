"""
Test for coi run - bridge forwarding that already works, with sudo for nft only.

Tests that:
1. On a host whose FORWARD chain already accepts the Incus bridge's traffic,
   a sudoers rule that grants nft but not iptables does not make `coi run`
   warn "could not ensure bridge forwarding rules"
2. coi reads the chain through nft instead and changes nothing
3. The container still starts and runs the command in restricted mode (both
   launch phases that check the bridge run)

The nft-only sudoers rule is simulated with a `sudo` shim on PATH that refuses
iptables like a missing NOPASSWD rule and passes everything else to sudo.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SENTINEL = "BRIDGE_FORWARD_OK_5208"


def _sudo_ok(*argv):
    try:
        return (
            subprocess.run(["sudo", "-n", *argv], capture_output=True, timeout=10).returncode == 0
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _iptables_is_nft():
    try:
        out = subprocess.run(["iptables", "-V"], capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return "nf_tables" in out.stdout


def _nft_only_sudo_shim(tmp_path):
    """Write a `sudo` that refuses iptables; return (bin dir, refusal log)."""
    real_sudo = shutil.which("sudo")
    bin_dir = Path(tmp_path) / "shim-bin"
    bin_dir.mkdir()
    refused = Path(tmp_path) / "refused.log"
    shim = bin_dir / "sudo"
    shim.write_text(f"""#!/bin/sh
cmd=""
for a in "$@"; do case "$a" in -*) ;; *) cmd="$a"; break ;; esac; done
case "$(basename "$cmd")" in
iptables*|ip6tables*)
    echo "$*" >> "{refused}"
    echo "sudo: a password is required" >&2
    exit 1 ;;
esac
exec "{real_sudo}" "$@"
""")
    shim.chmod(0o755)
    return bin_dir, refused


def test_working_forwarding_with_nft_only_sudo_does_not_warn(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    Flow:
    1. Skip unless sudo runs iptables and nft and iptables is the nf_tables
       variant (nft then sees the iptables FORWARD chain)
    2. Run `coi run` once with real sudo, so the bridge forwarding works
    3. Run `coi run` in restricted mode with sudo refusing iptables
    4. Verify it succeeds, prints no bridge forwarding warning and tried
       iptables only to read the chain (no -C probes, no -I inserts)
    """
    if not _sudo_ok("iptables", "-S", "FORWARD") or not _sudo_ok("nft", "list", "tables"):
        pytest.skip("needs passwordless sudo for iptables and nft")
    if not _iptables_is_nft():
        pytest.skip("iptables is not the nf_tables variant")

    cfg = Path(tmp_path) / "trusted-config.toml"
    cfg.write_text('[network]\nmode = "restricted"\n')
    env = dict(os.environ)
    env["COI_CONFIG"] = str(cfg)

    warm = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "echo", SENTINEL],
        capture_output=True,
        text=True,
        timeout=240,
        env=env,
    )
    assert warm.returncode == 0, (
        f"coi run with real sudo should succeed. stdout={warm.stdout} stderr={warm.stderr}"
    )

    bin_dir, refused = _nft_only_sudo_shim(tmp_path)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "echo", SENTINEL],
        capture_output=True,
        text=True,
        timeout=240,
        env=env,
    )
    combined = result.stdout + result.stderr

    assert result.returncode == 0, (
        f"coi run should succeed with nft-only sudo. stdout={result.stdout} stderr={result.stderr}"
    )
    assert SENTINEL in result.stdout, f"command did not run in the container. out={combined}"
    assert "could not ensure bridge forwarding rules" not in combined, (
        f"working forwarding must not warn. out={combined}"
    )

    calls = refused.read_text().splitlines() if refused.exists() else []
    assert calls, "the sudo shim was not used: no iptables call was refused"
    assert all(" -S FORWARD" in c for c in calls), (
        f"iptables should only be read, never probed or changed. refused={calls}"
    )
