"""
Test for coi shell - a profile from [defaults] profile is not saved into an alias.

Tests that:
1. `coi shell` whose only profile is [defaults] profile registers the alias in
   ~/.coi/aliases.json without a profile
2. After a change of [defaults] profile, `coi shell <alias>` runs the new default
3. `coi shell --profile <name>` saves the profile, and `coi shell <alias>` runs
   that saved profile and keeps it, while [defaults] profile names another one;
   a later default-only `coi shell` keeps the saved profile too
4. `coi shell --resume` of a session whose profile came only from [defaults]
   profile (`profile_from_default` in its metadata) does not save the profile

A fake HOME keeps ~/.coi/config.toml, the profiles, the alias registry and the
saved sessions (~/.coi/sessions-claude) to this test.
"""

import json
import os
import subprocess

from support.helpers import kill_workspace_containers, write_workspace_container_config

ALIAS = "defprofalias"


def _setup_home(tmp_path):
    """Create a fake HOME with profiles 'pa' and 'pb' in ~/.coi/profiles."""
    fake_home = tmp_path / "fake_home"
    for name in ("pa", "pb"):
        profile_dir = fake_home / ".coi" / "profiles" / name
        profile_dir.mkdir(parents=True)
        (profile_dir / "config.toml").write_text("[container]\n")
    env = {**os.environ, "HOME": str(fake_home), "COI_USE_DUMMY": "1"}
    env.pop("COI_CONFIG", None)
    return fake_home, env


def _set_default_profile(fake_home, name):
    (fake_home / ".coi" / "config.toml").write_text(f'[defaults]\nprofile = "{name}"\n')


def _shell(coi_binary, cwd, env, *args):
    result = subprocess.run(
        [coi_binary, "shell", "--background", *args],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=cwd,
        env=env,
    )
    assert result.returncode == 0, (
        f"coi shell --background {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}"
    )
    return result


def _alias_entry(fake_home):
    path = fake_home / ".coi" / "aliases.json"
    assert path.is_file(), "coi shell did not write ~/.coi/aliases.json"
    return json.loads(path.read_text()).get(ALIAS)


def _sessions(fake_home):
    """Map of saved session ID to its metadata."""
    sessions_dir = fake_home / ".coi" / "sessions-claude"
    if not sessions_dir.is_dir():
        return {}
    return {
        entry.name: json.loads((entry / "metadata.json").read_text())
        for entry in sessions_dir.iterdir()
        if (entry / "metadata.json").is_file()
    }


def _new_session(fake_home, before):
    """Metadata of the one session saved since `before` (a _sessions result)."""
    new = {sid: m for sid, m in _sessions(fake_home).items() if sid not in before}
    assert len(new) == 1, f"expected one new saved session, got: {list(new)}"
    return next(iter(new.items()))


def test_default_profile_not_saved_into_alias(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, dummy_image
):
    """
    A default-only profile is not saved, so a later default applies to
    `coi shell <alias>`.

    Flow:
    1. [defaults] profile = "pa"; coi shell --background in the workspace
    2. The alias entry has no profile; the session ran 'pa' from the default
    3. [defaults] profile = "pb"; coi shell --background <alias> from another dir
    4. The session ran 'pb'; the alias entry still has no profile
    """
    fake_home, env = _setup_home(tmp_path)
    write_workspace_container_config(workspace_dir, image=dummy_image, alias=ALIAS)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    # === Phase 1: launch with only [defaults] profile ===

    _set_default_profile(fake_home, "pa")
    _shell(coi_binary, workspace_dir, env)
    kill_workspace_containers(coi_binary, workspace_dir, env)

    assert _alias_entry(fake_home) == {"workspace": workspace_dir}, (
        f"[defaults] profile must not be saved into the alias: {_alias_entry(fake_home)}"
    )
    _, metadata = _new_session(fake_home, {})
    assert metadata["profile_name"] == "pa", f"the session should run 'pa': {metadata}"
    assert metadata.get("profile_from_default") is True, (
        f"the session should mark 'pa' as from [defaults] profile: {metadata}"
    )

    # === Phase 2: a changed default applies to coi shell <alias> ===

    _set_default_profile(fake_home, "pb")
    before = _sessions(fake_home)
    _shell(coi_binary, str(elsewhere), env, ALIAS)
    kill_workspace_containers(coi_binary, workspace_dir, env)

    _, metadata = _new_session(fake_home, before)
    assert metadata["profile_name"] == "pb", (
        f"coi shell {ALIAS} should run the new default 'pb': {metadata}"
    )
    assert _alias_entry(fake_home) == {"workspace": workspace_dir}, (
        f"[defaults] profile must not be saved into the alias: {_alias_entry(fake_home)}"
    )


def test_explicit_and_alias_profile_saved(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, dummy_image
):
    """
    --profile is saved into the alias, and the alias's own profile wins over
    [defaults] profile and stays saved, also across a default-only launch.

    Flow:
    1. [defaults] profile = "pa"; coi shell --background --profile pb
    2. The alias entry has profile 'pb'
    3. coi shell --background <alias> from another dir
    4. The session ran 'pb', not from the default; the entry still has 'pb'
    5. coi shell --background in the workspace (no --profile, no alias)
    6. The session ran 'pa' from the default; the entry still has 'pb'
    """
    fake_home, env = _setup_home(tmp_path)
    write_workspace_container_config(workspace_dir, image=dummy_image, alias=ALIAS)
    _set_default_profile(fake_home, "pa")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    # === Phase 1: --profile is saved ===

    _shell(coi_binary, workspace_dir, env, "--profile", "pb")
    kill_workspace_containers(coi_binary, workspace_dir, env)

    expected = {"workspace": workspace_dir, "profile": "pb"}
    assert _alias_entry(fake_home) == expected, (
        f"coi shell --profile pb should save the profile: {_alias_entry(fake_home)}"
    )

    # === Phase 2: the alias's profile is used and kept ===

    before = _sessions(fake_home)
    _shell(coi_binary, str(elsewhere), env, ALIAS)
    kill_workspace_containers(coi_binary, workspace_dir, env)

    _, metadata = _new_session(fake_home, before)
    assert metadata["profile_name"] == "pb", (
        f"coi shell {ALIAS} should run the alias's profile 'pb': {metadata}"
    )
    assert not metadata.get("profile_from_default"), (
        f"the alias's profile must not be marked as from [defaults] profile: {metadata}"
    )
    assert _alias_entry(fake_home) == expected, (
        f"coi shell {ALIAS} should keep the saved profile: {_alias_entry(fake_home)}"
    )

    # === Phase 3: a default-only launch keeps the saved profile ===

    before = _sessions(fake_home)
    _shell(coi_binary, workspace_dir, env)
    kill_workspace_containers(coi_binary, workspace_dir, env)

    _, metadata = _new_session(fake_home, before)
    assert metadata["profile_name"] == "pa" and metadata.get("profile_from_default") is True, (
        f"a bare coi shell should run the default 'pa': {metadata}"
    )
    assert _alias_entry(fake_home) == expected, (
        f"a default-only launch must keep the saved profile: {_alias_entry(fake_home)}"
    )


def test_resume_of_default_profile_session_not_saved(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, dummy_image
):
    """
    A resume inherits a default-only profile from the session but does not save
    it into the alias.

    Flow:
    1. [defaults] profile = "pa"; coi shell --background; coi kill
    2. [defaults] profile = "pb"; coi shell --background --resume=<id>
    3. The resume inherits 'pa', still marked as from the default
    4. The alias entry has no profile
    """
    fake_home, env = _setup_home(tmp_path)
    write_workspace_container_config(workspace_dir, image=dummy_image, alias=ALIAS)

    # === Phase 1: save a default-only session ===

    _set_default_profile(fake_home, "pa")
    _shell(coi_binary, workspace_dir, env)
    kill_workspace_containers(coi_binary, workspace_dir, env)
    session_id, metadata = _new_session(fake_home, {})
    assert metadata.get("profile_from_default") is True, (
        f"the session should mark 'pa' as from [defaults] profile: {metadata}"
    )

    # === Phase 2: resume it ===

    _set_default_profile(fake_home, "pb")
    result = _shell(coi_binary, workspace_dir, env, f"--resume={session_id}")
    kill_workspace_containers(coi_binary, workspace_dir, env)

    assert "Inherited profile 'pa' from session" in result.stderr, (
        f"the resume should inherit the session's profile 'pa':\n{result.stderr}"
    )
    metadata = _sessions(fake_home)[session_id]
    assert metadata["profile_name"] == "pa" and metadata.get("profile_from_default") is True, (
        f"the resumed session should keep 'pa' marked as from the default: {metadata}"
    )
    assert _alias_entry(fake_home) == {"workspace": workspace_dir}, (
        f"a resume must not save a default-only profile into the alias: {_alias_entry(fake_home)}"
    )
