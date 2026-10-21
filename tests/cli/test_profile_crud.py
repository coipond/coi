"""
Tests for profile create, edit, and delete commands (Issue #114, Phase 2).
"""

import os
import subprocess


def test_profile_create_basic(coi_binary, tmp_path):
    """coi profile create should create the profile directory and config.toml."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    result = subprocess.run(
        [coi_binary, "profile", "create", "test-basic", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )

    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}: {result.stderr}"
    assert "Created profile 'test-basic'" in result.stderr

    config_path = home_coi / "profiles" / "test-basic" / "config.toml"
    assert config_path.exists(), f"config.toml not created at {config_path}"

    assert config_path.read_text() == "", "scaffold is empty — settings are edited in"


def test_profile_create_with_inherits(coi_binary, tmp_path):
    """coi profile create with --inherits should set the inherits field."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "create",
            "test-inherit",
            "--inherits",
            "default",
            "--user",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )

    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}: {result.stderr}"

    config_path = home_coi / "profiles" / "test-inherit" / "config.toml"
    content = config_path.read_text()
    assert 'inherits = "default"' in content


def test_profile_create_rejects_removed_flags(coi_binary, tmp_path):
    """The removed --image/--persistent flags fail on profile create too — the
    profile's config.toml is the only authoring surface (edit it afterwards)."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    result = subprocess.run(
        [coi_binary, "profile", "create", "test-persist", "--persistent", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )

    assert result.returncode != 0, "removed flag must fail on profile create as well"
    assert "flag was removed" in result.stderr, f"want migration hint, got:\n{result.stderr}"
    assert not (home_coi / "profiles" / "test-persist").exists()


def test_profile_create_duplicate_fails(coi_binary, tmp_path):
    """Creating a profile with the same name twice should fail."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    env = {**os.environ, "HOME": str(tmp_path)}

    # First create succeeds
    result = subprocess.run(
        [coi_binary, "profile", "create", "test-dup", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0

    # Second create fails
    result = subprocess.run(
        [coi_binary, "profile", "create", "test-dup", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode != 0
    assert "already exists" in result.stderr


def test_profile_create_default_scaffolds_main_config(coi_binary, tmp_path):
    """`coi profile create default` scaffolds the main config (the file backing the
    built-in default profile), rather than creating a profile directory.

    (Previously this name was rejected as reserved; see #482 and the dedicated
    tests in test_profile_create_default.py.)"""
    result = subprocess.run(
        [coi_binary, "profile", "create", "default", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )

    assert result.returncode == 0, f"should scaffold the main config. stderr: {result.stderr}"
    assert (tmp_path / ".coi" / "config.toml").is_file()
    # It writes the main config, NOT a profiles/default/ directory.
    assert not (tmp_path / ".coi" / "profiles" / "default").exists()


def test_profile_create_project_flag(coi_binary, tmp_path):
    """--project should create the profile in .coi/profiles/ under the workspace."""
    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "create",
            "test-proj",
            "--project",
            "--workspace",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}: {result.stderr}"

    config_path = tmp_path / ".coi" / "profiles" / "test-proj" / "config.toml"
    assert config_path.exists(), f"config.toml not created at {config_path}"


def test_profile_create_dot_names_rejected(coi_binary, tmp_path):
    """Profile names like '.' and '..' should be rejected (path traversal)."""
    for dot_name in [".", "..", "..."]:
        result = subprocess.run(
            [coi_binary, "profile", "create", dot_name, "--user"],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "HOME": str(tmp_path)},
        )

        assert result.returncode != 0, f"Name '{dot_name}' should be rejected"
        assert "dots" in result.stderr.lower() or "cannot be" in result.stderr.lower()


def test_profile_create_slash_in_name_rejected(coi_binary, tmp_path):
    """Profile names with slashes should be rejected."""
    result = subprocess.run(
        [coi_binary, "profile", "create", "bad/name", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )

    assert result.returncode != 0
    assert "slash" in result.stderr.lower()


def test_profile_create_user_and_project_mutually_exclusive(coi_binary, tmp_path):
    """--user and --project together should fail."""
    result = subprocess.run(
        [coi_binary, "profile", "create", "test-both", "--user", "--project"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )

    assert result.returncode != 0
    assert "mutually exclusive" in result.stderr.lower()


def test_profile_delete_basic(coi_binary, tmp_path):
    """Create then delete with --force should remove the profile."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    env = {**os.environ, "HOME": str(tmp_path)}

    # Create
    result = subprocess.run(
        [coi_binary, "profile", "create", "test-del", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0

    profile_dir = home_coi / "profiles" / "test-del"
    assert profile_dir.exists()

    # Delete
    result = subprocess.run(
        [coi_binary, "profile", "delete", "test-del", "--force"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}: {result.stderr}"
    assert "Deleted profile 'test-del'" in result.stderr
    assert not profile_dir.exists()


def test_profile_delete_nonexistent_fails(coi_binary):
    """Deleting a profile that doesn't exist should fail."""
    result = subprocess.run(
        [coi_binary, "profile", "delete", "no-such-profile", "--force"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "not found" in result.stderr


def test_profile_delete_builtin_fails(coi_binary):
    """Deleting the built-in 'default' profile should fail."""
    result = subprocess.run(
        [coi_binary, "profile", "delete", "default", "--force"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "built-in" in result.stderr.lower()


def test_profile_delete_hardened_builtin_fails(coi_binary, tmp_path):
    """Deleting the built-in 'hardened' profile fails, and the error names it."""
    result = subprocess.run(
        [coi_binary, "profile", "delete", "hardened", "--force"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=tmp_path,
        env={**os.environ, "HOME": str(tmp_path)},
    )

    assert result.returncode != 0
    assert "cannot delete built-in profile 'hardened'" in result.stderr, result.stderr


def _assert_disk_builtin_delete_refused(coi_binary, name, profile_dir, cwd, home):
    (profile_dir / "config.toml").parent.mkdir(parents=True)
    (profile_dir / "config.toml").write_text("")

    result = subprocess.run(
        [coi_binary, "profile", "delete", name, "--force"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=cwd,
        env={**os.environ, "HOME": str(home)},
    )

    assert result.returncode != 0, f"delete of disk '{name}' must fail:\n{result.stderr}"
    assert f"cannot delete profile '{name}'" in result.stderr, result.stderr
    assert str(profile_dir) in result.stderr, result.stderr
    assert "Deleted profile" not in result.stderr
    assert (profile_dir / "config.toml").exists(), "the profile directory must be kept"


def test_profile_delete_disk_default_user_refused(coi_binary, tmp_path):
    """A user ~/.coi/profiles/default replaces the built-in 'default', but
    `profile delete default` still refuses and keeps the directory."""
    home, ws = tmp_path / "home", tmp_path / "ws"
    ws.mkdir()
    _assert_disk_builtin_delete_refused(
        coi_binary, "default", home / ".coi" / "profiles" / "default", ws, home
    )


def test_profile_delete_disk_default_project_refused(coi_binary, tmp_path):
    """A project .coi/profiles/default is refused the same way."""
    home, ws = tmp_path / "home", tmp_path / "ws"
    home.mkdir()
    _assert_disk_builtin_delete_refused(
        coi_binary, "default", ws / ".coi" / "profiles" / "default", ws, home
    )


def test_profile_delete_disk_hardened_refused(coi_binary, tmp_path):
    """A disk profile named 'hardened' is refused too."""
    home, ws = tmp_path / "home", tmp_path / "ws"
    ws.mkdir()
    _assert_disk_builtin_delete_refused(
        coi_binary, "hardened", home / ".coi" / "profiles" / "hardened", ws, home
    )


def test_profile_edit_nonexistent_fails(coi_binary):
    """Editing a profile that doesn't exist should fail."""
    result = subprocess.run(
        [coi_binary, "profile", "edit", "no-such-profile"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "not found" in result.stderr


def test_profile_edit_builtin_fails(coi_binary):
    """Editing the built-in 'default' profile should fail."""
    result = subprocess.run(
        [coi_binary, "profile", "edit", "default"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "built-in" in result.stderr.lower()


def test_profile_create_visible_in_list(coi_binary, tmp_path):
    """A newly created profile should appear in 'profile list'."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    env = {**os.environ, "HOME": str(tmp_path)}

    result = subprocess.run(
        [coi_binary, "profile", "create", "list-test", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0

    result = subprocess.run(
        [coi_binary, "profile", "list"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0
    assert "list-test" in result.stdout


def test_profile_create_no_flags_produces_empty_config(coi_binary, tmp_path):
    """Creating a profile without --inherits produces an empty config to edit."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    result = subprocess.run(
        [coi_binary, "profile", "create", "bare-profile", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.returncode == 0

    config_path = home_coi / "profiles" / "bare-profile" / "config.toml"
    assert config_path.exists()
    assert config_path.read_text() == ""


def test_profile_create_auto_detects_project(coi_binary, tmp_path):
    """Without --user/--project, create should use project .coi/ if it exists."""
    # Set up a project with .coi/ directory
    project_coi = tmp_path / ".coi"
    project_coi.mkdir()

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "create",
            "auto-proj",
            "--workspace",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}: {result.stderr}"

    config_path = project_coi / "profiles" / "auto-proj" / "config.toml"
    assert config_path.exists(), f"Expected profile at project location {config_path}"


def test_profile_create_duplicate_across_locations_fails(coi_binary, tmp_path):
    """Creating a profile name that already exists in another location should fail."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    env = {**os.environ, "HOME": str(tmp_path)}

    # Create at user level
    result = subprocess.run(
        [coi_binary, "profile", "create", "cross-dup", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0

    # Try to create same name at project level — should fail because name exists in cfg
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / ".coi").mkdir()

    result = subprocess.run(
        [
            coi_binary,
            "profile",
            "create",
            "cross-dup",
            "--project",
            "--workspace",
            str(project_dir),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode != 0
    assert "already exists" in result.stderr


def test_profile_edit_with_true_editor(coi_binary, tmp_path):
    """Edit with EDITOR=true should succeed (true exits 0 without modifying)."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    env = {**os.environ, "HOME": str(tmp_path)}

    # Create a profile first
    result = subprocess.run(
        [coi_binary, "profile", "create", "edit-test", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0

    # Edit with EDITOR=true (no-op editor that exits 0)
    result = subprocess.run(
        [coi_binary, "profile", "edit", "edit-test"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**env, "EDITOR": "true", "VISUAL": ""},
    )
    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}: {result.stderr}"


def test_profile_delete_short_flag(coi_binary, tmp_path):
    """The -f short flag should work the same as --force."""
    home_coi = tmp_path / ".coi"
    home_coi.mkdir()

    env = {**os.environ, "HOME": str(tmp_path)}

    # Create
    result = subprocess.run(
        [coi_binary, "profile", "create", "test-sf", "--user"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0

    # Delete with -f
    result = subprocess.run(
        [coi_binary, "profile", "delete", "test-sf", "-f"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}: {result.stderr}"
    assert "Deleted profile 'test-sf'" in result.stderr
