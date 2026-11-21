"""
Test for coi build --all - removes a superseded Ubuntu base cache alias.

Tests that:
1. A coi-ubuntu-<ver> alias whose version no build uses is removed after
   `coi build --all` built at least one image
2. The image holding it keeps its other alias (coi-default): only the alias
   goes
"""

import subprocess

import pytest

from support.helpers import image_fingerprint, stale_ubuntu_cache_alias, write_profile

STALE_ALIAS = "coi-ubuntu-20.04"


def test_build_all_prunes_ubuntu_cache(coi_binary, workspace_dir):
    """
    Flow:
    1. Add alias coi-ubuntu-20.04 to the coi-default image
    2. `coi build --all` with one custom profile built from coi-default
    3. The alias is gone; coi-default is still the same image
    """
    image_name = "coi-test-build-all-prune-cache"
    subprocess.run([coi_binary, "image", "delete", image_name], check=False, capture_output=True)
    write_profile(
        workspace_dir,
        "prune",
        f'[container]\nimage = "{image_name}"\n\n'
        '[container.build]\nbase = "coi-default"\ncommands = ["true"]\n',
    )

    with stale_ubuntu_cache_alias(STALE_ALIAS) as fingerprint:
        if fingerprint is None:
            pytest.skip("coi-default missing or used by an instance")
        try:
            result = subprocess.run(
                [coi_binary, "build", "--all"],
                capture_output=True,
                text=True,
                timeout=600,
                cwd=workspace_dir,
            )
            assert result.returncode == 0, f"Build should succeed. stderr: {result.stderr}"
            assert f"Removed unused alias '{STALE_ALIAS}'" in result.stderr, result.stderr
            assert image_fingerprint(STALE_ALIAS) is None, "stale cache alias should be gone"
            assert image_fingerprint("coi-default") == fingerprint, "coi-default must stay"
        finally:
            subprocess.run(
                [coi_binary, "image", "delete", image_name], check=False, capture_output=True
            )
