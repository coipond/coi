"""
Built-in "hardened" profile: a one-flag hardened preset for opening untrusted /
freshly-cloned repos (`coi shell --profile hardened`). Issue #496.

It bundles Coi's strongest EXISTING controls (no new enforcement): restricted
network, secret masking, host immutability, ephemeral container, no SSH-agent
forwarding, and threat monitoring. It ships built-in (no disk profile needed),
so these checks need neither incus nor sudo — they assert the preset is present
and shows the hardened settings via `coi profile`.
"""

import subprocess


def _run(coi_binary, *args, timeout=30):
    return subprocess.run([coi_binary, *args], capture_output=True, text=True, timeout=timeout)


def test_hardened_profile_is_builtin(coi_binary):
    """`coi profile list` must include the built-in hardened profile."""
    r = _run(coi_binary, "profile", "list")
    assert r.returncode == 0, f"profile list failed: {r.stderr}"
    assert "hardened" in r.stdout, f"built-in 'hardened' profile missing from list:\n{r.stdout}"


def test_hardened_profile_hardened_settings(coi_binary):
    """`coi profile info hardened` must show the hardened preset."""
    r = _run(coi_binary, "profile", "info", "hardened")
    assert r.returncode == 0, f"profile info hardened failed: {r.stderr}"
    out = r.stdout

    expected = [
        'mode = "restricted"',  # no exfil path
        "persistent = false",  # ephemeral
        "forward_agent = false",  # never forward host SSH agent
        "host_immutable = true",  # host-side immutability
        "reduce_kernel_surface = true",  # kernel attack-surface hardening (also disables docker)
        'max_duration = "4h"',  # bounded session (12h+ persistence enabled the ToB escapes)
        "secret_paths = [",  # secret masking bundled
        ".env",  # a sensible default secret
        "*.tfstate",  # broadened secret-mask defaults (terraform state)
        ".git-credentials",  # broadened secret-mask defaults
        "enabled = true",  # monitoring on
    ]
    for token in expected:
        assert token in out, f"hardened profile info missing {token!r}:\n{out}"
