"""
Using a profile with invalid settings must fail, with an error naming the
problem — before any container is created.

Covers the cases of a reported "ProfileConfig.Validate accepts invalid ..."
issue (which was generated against a mutated copy of validate.go; the real code
rejects all of them): an invalid credential mode, a mount without a container
path, duplicate port names, container port 0, and a single invalid
[[network.hosts]] entry. Some are rejected by the profile JSON schema at load,
the rest by ProfileConfig.Validate when the profile is applied; either way the
command must fail.
"""

import os
import subprocess

import pytest

CASES = [
    (
        "credential-mode",
        '[[credentials]]\nbundle = "ollama"\nmode = "0999"\n',
        "invalid 'mode'",
    ),
    (
        "mount-without-container",
        '[[mounts]]\nhost = "/tmp"\n',
        "missing property 'container'",
    ),
    (
        "duplicate-port-names",
        '[ports]\n[[ports.map]]\nname = "web"\ncontainer = 3000\n'
        '[[ports.map]]\nname = "web"\ncontainer = 4000\n',
        'duplicates name "web"',
    ),
    (
        "container-port-0",
        '[ports]\n[[ports.map]]\nname = "web"\ncontainer = 0\n',
        "minimum: got 0, want 1",
    ),
    (
        "single-invalid-network-host",
        '[network]\n[[network.hosts]]\nip = "not-an-ip"\nhostnames = ["db"]\n',
        "not a valid IPv4 address",
    ),
]


@pytest.mark.parametrize("body,expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_invalid_profile_is_rejected(coi_binary, tmp_path, workspace_dir, body, expected):
    cfg_dir = tmp_path / "coi-config"
    (cfg_dir / "profiles" / "bad").mkdir(parents=True)
    (cfg_dir / "profiles" / "bad" / "config.toml").write_text(body)
    (cfg_dir / "config.toml").write_text("")
    env = {**os.environ, "COI_CONFIG": str(cfg_dir / "config.toml")}

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--profile", "bad", "--", "true"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode != 0, (
        f"using an invalid profile must fail; stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert expected in result.stderr, f"expected {expected!r} in the error:\n{result.stderr}"


def test_valid_profile_passes_validation(coi_binary, tmp_path, workspace_dir):
    """Control: the same settings, made valid, pass validation."""
    cfg_dir = tmp_path / "coi-config"
    (cfg_dir / "profiles" / "good").mkdir(parents=True)
    (cfg_dir / "profiles" / "good" / "config.toml").write_text(
        '[[credentials]]\nbundle = "ollama"\nmode = "0600"\n'
        '[[mounts]]\nhost = "/tmp"\ncontainer = "/mnt/host-tmp"\n'
        '[ports]\n[[ports.map]]\nname = "web"\ncontainer = 3000\n'
        '[network]\n[[network.hosts]]\nip = "10.0.0.5"\nhostnames = ["db"]\n'
    )
    (cfg_dir / "config.toml").write_text("")
    # `coi profile edit` re-validates the profile after the editor exits; a
    # no-op editor makes it a plain validation run of ProfileConfig.Validate.
    env = {
        **os.environ,
        "COI_CONFIG": str(cfg_dir / "config.toml"),
        "EDITOR": "true",
        "VISUAL": "true",
    }
    result = subprocess.run(
        [coi_binary, "profile", "edit", "good"], capture_output=True, text=True, timeout=30, env=env
    )
    assert result.returncode == 0, f"a valid profile should load:\n{result.stderr}"
    assert "profile validation failed" not in result.stderr, result.stderr
    for needle in (
        "invalid 'mode'",
        "duplicates name",
        "missing property",
        "minimum:",
        "not a valid IPv4",
    ):
        assert needle not in result.stderr
