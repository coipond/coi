"""
A network-isolation setup failure must fail CLOSED: the session aborts rather
than running the command with an un-isolated (potentially open) network.

Coi applies a boot block (zero egress) right after the container starts and lifts
it only once the mode's firewall rules are in place; on a `setupRestricted` /
`setupAllowlist` error it deliberately keeps the block and returns the error
(`internal/network/manager.go`). If a refactor lifted the block on the error path
instead, a failed setup would silently proceed with an open network. This e2e
proves the user-observable half of that invariant end to end (the boot-block nft
rule itself is asserted by the Go integration test
`TestSetupForContainer_SetupError_KeepsBootBlock_Integration`, which needs incus).

The failure is induced with an allowlist whose only domain cannot resolve
(`.invalid` is reserved as always-NXDOMAIN, RFC 6761), so `setupAllowlist` errors
with "failed to resolve any allowlisted hostname".
"""

import subprocess

from support.helpers import write_trusted_coi_config


def test_network_setup_failure_fails_closed(coi_binary, cleanup_containers, workspace_dir):
    """`coi run` aborts (and never runs the command) when allowlist setup fails."""
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "allowlist"\n'
        'allowed_domains = ["nonexistent-coi-failclosed-zzz.invalid"]\n'
    )

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", "echo SESSION_RAN"],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
        env=env,
    )

    combined = (result.stdout + result.stderr).lower()

    # Fail closed: a non-zero exit, and the command must NOT have executed. If the
    # boot block were lifted on the setup error (fail OPEN), the pipeline would
    # continue and the command would run with an un-isolated network.
    assert result.returncode != 0, (
        "coi run should FAIL CLOSED when allowlist setup cannot resolve its only domain, "
        f"not proceed with an un-isolated session.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "SESSION_RAN" not in result.stdout, (
        "the command ran despite a network-setup failure — the session was NOT fail-closed "
        f"(isolation was skipped / the boot block lifted on error).\nstdout: {result.stdout}"
    )
    # Attribute the failure to the network setup (not some unrelated launch error),
    # so this can't pass vacuously if coi run happens to fail for another reason.
    assert any(tok in combined for tok in ("resolve", "allowlist", "network", "domain")), (
        "coi run failed, but not visibly due to the network-isolation setup — the fail-closed "
        f"path is not attributable.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
