"""
A profile may set any config key coi supports. Profiles are validated against
the JSON schema (unknown keys rejected), so a key missing from the schema made
the profile fail to load — and with it every coi command, since config loading
aborts. Regression tests for keys that once hit this: [limits.disk] size and
[git] protected_branches. (internal/config TestProfileSchemaMatchesConfigStructs
guards the whole class at unit level.)
"""

import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "body",
    [
        '[limits.disk]\nsize = "20GiB"\n',
        '[git]\nprotected_branches = ["release"]\n',
    ],
    ids=["limits.disk.size", "git.protected_branches"],
)
def test_profile_with_key_loads(coi_binary, tmp_path, body):
    cfg_dir = tmp_path / "coi-config"
    profile = cfg_dir / "profiles" / "parity" / "config.toml"
    profile.parent.mkdir(parents=True)
    profile.write_text(body)
    (cfg_dir / "config.toml").write_text("")
    env = {**os.environ, "COI_CONFIG": str(cfg_dir / "config.toml")}

    for argv in (["profile", "info", "parity"], ["profile", "list"]):
        result = subprocess.run(
            [coi_binary, *argv], capture_output=True, text=True, timeout=30, env=env
        )
        assert result.returncode == 0, (
            f"`coi {' '.join(argv)}` failed with a profile setting this key:\n{result.stderr}"
        )
        assert "schema validation" not in result.stderr
    assert Path(profile).exists()
