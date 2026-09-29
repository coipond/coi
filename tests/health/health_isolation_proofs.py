"""
Runtime isolation proofs in `coi health` — the adversarial checks that verify
Coi's guarantees actually hold inside a container, not just that config parses:

  - secret_masking: plant a decoy secret in a workspace, mask it via secret_paths,
    and confirm it reads EMPTY inside the container (a leak is a hard failure).
  - network_restriction: now also asserts the cloud metadata endpoint
    (169.254.169.254) is blocked, not just RFC1918.

These checks launch an ephemeral container, so they require the coi-default image
+ nft. Where that isn't available the check reports "skipped" (Warning) and the
deep assertions are skipped rather than failing.
"""

import json
import subprocess

import pytest


@pytest.fixture(scope="module")
def health_json(coi_binary):
    """Run `coi health --format json` once (it launches probe containers)."""
    result = subprocess.run(
        [coi_binary, "health", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert result.returncode in (0, 1, 2), (
        f"health exited with unexpected code {result.returncode}. stderr: {result.stderr}"
    )
    return json.loads(result.stdout)


def _check(health_json, name):
    checks = health_json.get("checks", {})
    assert name in checks, f"'{name}' check missing from coi health output: {sorted(checks)}"
    return checks[name]


def test_secret_masking_check_present(health_json):
    """The secret_masking check must always be reported by `coi health`."""
    _check(health_json, "secret_masking")


def test_secret_masking_does_not_leak(health_json):
    """When the probe ran (image available), the masked secret must NOT be
    readable inside the container, and the control marker must be readable."""
    c = _check(health_json, "secret_masking")
    status = c.get("status")
    if status not in ("ok", "failed"):
        pytest.skip(f"secret_masking probe did not run (status={status}): {c.get('message')}")

    details = c.get("details") or {}
    assert details.get("secret_leaked") is False, (
        f"SECRET LEAK: a masked secret_paths file was readable inside the container. {c}"
    )
    assert status == "ok", f"secret_masking did not pass: {c.get('message')} {details}"
    assert details.get("control_readable") is True, (
        f"control marker should be readable (probe meaningful): {details}"
    )


def test_host_credential_isolation_check_present(health_json):
    """The host_credential_isolation check must always be reported."""
    _check(health_json, "host_credential_isolation")


def test_host_credentials_not_leaked(health_json):
    """When the probe ran, a decoy planted in the host home must NOT be readable
    inside the container (Coi's 'credentials never exposed' guarantee)."""
    c = _check(health_json, "host_credential_isolation")
    status = c.get("status")
    if status not in ("ok", "failed"):
        pytest.skip(
            f"host_credential_isolation probe did not run (status={status}): {c.get('message')}"
        )

    details = c.get("details") or {}
    assert details.get("decoy_leaked") is False, (
        f"HOST CREDENTIAL LEAK: host home is reachable inside the container. {c}"
    )
    assert status == "ok", f"host_credential_isolation did not pass: {c.get('message')} {details}"


def test_network_restriction_blocks_metadata_endpoint(health_json):
    """When restricted-mode probe ran, it must verify the cloud metadata
    endpoint (169.254.169.254) is blocked."""
    c = _check(health_json, "network_restriction")
    status = c.get("status")
    if status not in ("ok", "failed"):
        pytest.skip(f"network_restriction probe did not run (status={status}): {c.get('message')}")

    details = c.get("details") or {}
    assert "metadata_blocked" in details, (
        f"network_restriction must report metadata_blocked: {details}"
    )
    if status == "ok":
        assert details.get("metadata_blocked") is True, (
            f"restricted mode must block the metadata endpoint: {details}"
        )
