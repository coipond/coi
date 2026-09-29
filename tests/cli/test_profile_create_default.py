"""
Integration tests for `coi profile create default` (issue #482).

`coi profile create default` scaffolds the MAIN config (the file backing the
built-in default profile): ~/.coi/config.toml by default, ./.coi/config.toml with
--project. It writes a documented starter only when no config exists there (never
overwrites), and rejects profile-only flags. Coi needs no config to run, so this
is onboarding convenience.

No container/incus needed — these only exercise the file-scaffolding command.
"""

import os
import subprocess


def run_coi(coi_binary, args, home, cwd=None, timeout=60):
    """Run coi with an isolated $HOME so the real ~/.coi is never touched."""
    env = os.environ.copy()
    env["HOME"] = str(home)
    return subprocess.run(
        [coi_binary, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        env=env,
    )


def test_create_default_writes_user_config(coi_binary, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()

    r = run_coi(coi_binary, ["profile", "create", "default"], home, cwd=cwd)
    assert r.returncode == 0, f"create default should succeed. stderr: {r.stderr}"

    cfg = home / ".coi" / "config.toml"
    assert cfg.is_file(), "expected ~/.coi/config.toml to be created"
    text = cfg.read_text()
    assert "starter template" in text, "should be the documented starter template"
    assert "[container]" in text
    assert "[network]" in text
    # Values are commented (override nothing by default).
    assert '# image = "coi-default"' in text

    # The generated config must still load cleanly (a read-only command works).
    r2 = run_coi(coi_binary, ["profile", "list"], home, cwd=cwd)
    assert r2.returncode == 0, f"coi should run with the generated config. stderr: {r2.stderr}"


def test_create_default_refuses_when_exists(coi_binary, tmp_path):
    home = tmp_path / "home"
    (home / ".coi").mkdir(parents=True)
    cfg = home / ".coi" / "config.toml"
    sentinel = '# my existing config\n[container]\nimage = "custom"\n'
    cfg.write_text(sentinel)

    r = run_coi(coi_binary, ["profile", "create", "default"], home, cwd=tmp_path)
    assert r.returncode != 0, "should refuse to overwrite an existing config"
    assert "already exists" in r.stderr.lower(), f"expected 'already exists'. stderr: {r.stderr}"
    assert cfg.read_text() == sentinel, "existing config must be left untouched"


def test_create_default_project_writes_project_config(coi_binary, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "project"
    ws.mkdir()

    r = run_coi(coi_binary, ["profile", "create", "default", "--project"], home, cwd=ws)
    assert r.returncode == 0, f"create default --project should succeed. stderr: {r.stderr}"
    assert (ws / ".coi" / "config.toml").is_file(), "expected ./.coi/config.toml in the project"
    # Did NOT also write the user config.
    assert not (home / ".coi" / "config.toml").exists(), "--project must not write the user config"


def test_create_default_rejects_profile_flags(coi_binary, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    r = run_coi(
        coi_binary, ["profile", "create", "default", "--inherits", "base"], home, cwd=tmp_path
    )
    assert r.returncode != 0, "profile-only flags should be rejected for 'create default'"
    assert "not valid" in r.stderr.lower(), f"expected a 'not valid' message. stderr: {r.stderr}"
    assert not (home / ".coi" / "config.toml").exists(), "no config should be written on rejection"


def test_create_named_profile_still_works(coi_binary, tmp_path):
    """Regression: non-default profile creation is unchanged."""
    home = tmp_path / "home"
    home.mkdir()

    r = run_coi(coi_binary, ["profile", "create", "myprof", "--user"], home, cwd=tmp_path)
    assert r.returncode == 0, f"creating a named profile should still work. stderr: {r.stderr}"
    assert (home / ".coi" / "profiles" / "myprof" / "config.toml").is_file(), (
        "named profile should be created under profiles/"
    )
    # And it must NOT have written a main config.
    assert not (home / ".coi" / "config.toml").exists()
