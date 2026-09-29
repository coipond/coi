"""
Test that profiles are loaded from ~/.coi/profiles/ and project .coi/profiles/
and merged into a single namespace, with duplicate names across locations
rejected as errors.

Profile scan locations (also dirname($COI_CONFIG) when set, but not tested here):
  - ~/.coi/profiles/
  - ./.coi/profiles/  (project-local)

Profiles from all discovered locations are merged together. If the same profile
name is defined in more than one location, Coi refuses to start and asks the
user to rename one.

Tests verify:
1. A profile placed in ~/.coi/profiles/ is picked up by `coi profile list`.
2. `coi profile info NAME` finds profiles under ~/.coi/profiles/.
3. Profiles from ~/.coi/profiles/ and project .coi/profiles/ are merged.
4. A duplicate profile name across locations produces a clear error with
   both paths referenced.
"""

import os
import subprocess
from pathlib import Path


def _env_with_home(fake_home: Path) -> dict:
    env = os.environ.copy()
    env["HOME"] = str(fake_home)
    # Unset COI_CONFIG so it doesn't interfere with profile dir detection
    env.pop("COI_CONFIG", None)
    return env


def test_profile_list_from_home_coi_dir(coi_binary, tmp_path):
    """Profile placed in ~/.coi/profiles/ should appear in `coi profile list`."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()

    prof_dir = fake_home / ".coi" / "profiles" / "home-coi-prof"
    prof_dir.mkdir(parents=True)
    (prof_dir / "config.toml").write_text('[container]\nimage = "home-coi-image"\n')

    # Run from a clean workspace so project .coi doesn't interfere
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = subprocess.run(
        [coi_binary, "profile", "list", "--workspace", str(workspace)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(workspace),
        env=_env_with_home(fake_home),
    )

    assert result.returncode == 0, f"profile list should succeed. stderr: {result.stderr}"
    output = result.stdout + result.stderr
    assert "home-coi-prof" in output, f"Should list profile from ~/.coi/profiles/. Got:\n{output}"
    assert "home-coi-image" in output, (
        f"Should show image from ~/.coi/profiles/ config. Got:\n{output}"
    )


def test_profile_info_from_home_coi_dir(coi_binary, tmp_path):
    """`coi profile info NAME` should find profiles under ~/.coi/profiles/."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()

    prof_dir = fake_home / ".coi" / "profiles" / "home-info-prof"
    prof_dir.mkdir(parents=True)
    (prof_dir / "config.toml").write_text('[container]\nimage = "home-info-image"\n')

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "info",
            "home-info-prof",
            "--workspace",
            str(workspace),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(workspace),
        env=_env_with_home(fake_home),
    )

    assert result.returncode == 0, f"profile info should succeed. stderr: {result.stderr}"
    output = result.stdout + result.stderr
    assert "home-info-prof" in output, f"Should show profile name. Got:\n{output}"
    assert "home-info-image" in output, (
        f"Should show image from ~/.coi/profiles/ config. Got:\n{output}"
    )


def test_profile_merges_home_and_project_locations(coi_binary, tmp_path):
    """
    Profiles from ~/.coi/profiles/ and project .coi/profiles/ should both be
    merged into a single namespace when their names are unique.
    """
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()

    # Profile in ~/.coi/profiles/
    home_prof = fake_home / ".coi" / "profiles" / "from-home"
    home_prof.mkdir(parents=True)
    (home_prof / "config.toml").write_text('[container]\nimage = "home-image"\n')

    # Project-local workspace with .coi/profiles/
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    proj_prof = workspace / ".coi" / "profiles" / "from-project"
    proj_prof.mkdir(parents=True)
    (proj_prof / "config.toml").write_text('[container]\nimage = "project-image"\n')

    list_result = subprocess.run(
        [coi_binary, "profile", "list", "--workspace", str(workspace)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(workspace),
        env=_env_with_home(fake_home),
    )

    assert list_result.returncode == 0, f"profile list should succeed. stderr: {list_result.stderr}"
    output = list_result.stdout + list_result.stderr
    assert "from-home" in output, f"Should list ~/.coi profile. Got:\n{output}"
    assert "from-project" in output, f"Should list project profile. Got:\n{output}"

    # Both should be individually resolvable via `profile info`
    for name, expected_image in [
        ("from-home", "home-image"),
        ("from-project", "project-image"),
    ]:
        info_result = subprocess.run(
            [
                coi_binary,
                "profile",
                "info",
                name,
                "--workspace",
                str(workspace),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(workspace),
            env=_env_with_home(fake_home),
        )
        assert info_result.returncode == 0, (
            f"profile info {name} should succeed. stderr: {info_result.stderr}"
        )
        info_output = info_result.stdout + info_result.stderr
        assert expected_image in info_output, (
            f"Profile {name} should show image {expected_image}. Got:\n{info_output}"
        )


def test_profile_duplicate_name_project_vs_home_fails(coi_binary, tmp_path):
    """
    Defining the same profile name in both a project-local .coi/profiles/
    and ~/.coi/profiles/ should cause Coi to exit with an error referencing
    both paths.
    """
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()

    home_prof = fake_home / ".coi" / "profiles" / "dup-proj"
    home_prof.mkdir(parents=True)
    (home_prof / "config.toml").write_text('[container]\nimage = "from-home"\n')

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    proj_prof = workspace / ".coi" / "profiles" / "dup-proj"
    proj_prof.mkdir(parents=True)
    (proj_prof / "config.toml").write_text('[container]\nimage = "from-project"\n')

    result = subprocess.run(
        [coi_binary, "profile", "list", "--workspace", str(workspace)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(workspace),
        env=_env_with_home(fake_home),
    )

    assert result.returncode != 0, (
        f"profile list should fail on duplicate profile. stdout: {result.stdout}"
    )
    combined = result.stdout + result.stderr
    assert "dup-proj" in combined, f"Error should mention profile name. Got:\n{combined}"
    assert "multiple locations" in combined.lower(), (
        f"Error should say 'multiple locations'. Got:\n{combined}"
    )
    assert str(home_prof / "config.toml") in combined, (
        f"Error should reference ~/.coi path. Got:\n{combined}"
    )
    assert str(proj_prof / "config.toml") in combined, (
        f"Error should reference project .coi path. Got:\n{combined}"
    )
