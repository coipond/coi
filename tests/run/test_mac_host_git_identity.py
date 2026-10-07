"""
Issue #853: inside a macOS VM (Colima/Lima/OrbStack), `coi run` must seed the
git identity from the Mac user's home, which the VM shares into the guest under
/Users, not from the VM's own gitconfig.

Runs only where COI_TEST_MAC_HOME names a Mac-style home shared under /Users
over virtiofs/9p. In CI that is the lima-smoke lane, which mounts a stand-in Mac
home at /Users/runner. On native runners the variable is unset and the test
skips. If the variable IS set but the mount is wrong, the test fails instead of
skipping, so a misconfigured lane cannot pass silently.

The guest's own identity is supplied via GIT_CONFIG_GLOBAL ("Guest VM"); the
Mac identity is written into the shared home. The contrast between the two
proves which source coi seeded into the container.
"""

import os
import subprocess

import pytest

GUEST_NAME, GUEST_EMAIL = "Guest VM", "vm@guest.test"
MAC_NAME, MAC_EMAIL = "Mac User", "mac@mac.test"

# Files this test writes into the shared Mac home; restored afterwards.
_TOUCHED = [".gitconfig", ".gitconfig-coi-853", os.path.join(".config", "git", "config")]


def _mac_home_or_skip():
    home = os.environ.get("COI_TEST_MAC_HOME")
    if not home:
        pytest.skip("COI_TEST_MAC_HOME not set (no Mac home shared under /Users)")
    with open("/proc/mounts") as f:
        mounts = [line.split() for line in f.read().splitlines()]
    shared = any(len(p) > 2 and p[1] == home and p[2] in ("virtiofs", "9p") for p in mounts)
    assert shared, f"COI_TEST_MAC_HOME={home} is not a virtiofs/9p mount point"
    assert os.access(home, os.W_OK), f"COI_TEST_MAC_HOME={home} is not writable"
    return home


@pytest.fixture
def mac_home():
    home = _mac_home_or_skip()
    saved = {}
    for rel in _TOUCHED:
        path = os.path.join(home, rel)
        saved[rel] = _read_bytes(path) if os.path.exists(path) else None
        if saved[rel] is not None:
            os.remove(path)
    yield home
    for rel, content in saved.items():
        path = os.path.join(home, rel)
        if content is None:
            if os.path.exists(path):
                os.remove(path)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(content)


@pytest.fixture
def guest_env(tmp_path):
    cfg = tmp_path / "guest-gitconfig"
    cfg.write_text(f"[user]\n\tname = {GUEST_NAME}\n\temail = {GUEST_EMAIL}\n")
    return {**os.environ, "GIT_CONFIG_GLOBAL": str(cfg)}


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def _seeded_identity(coi_binary, workspace_dir, env):
    """Return the (name, email) coi seeded into the container's global gitconfig."""
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            'echo "NAME=$(git config --global user.name)"; '
            'echo "EMAIL=$(git config --global user.email)"',
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 0, f"coi run failed:\n{out}"
    fields = dict(
        line.split("=", 1) for line in out.splitlines() if line.startswith(("NAME=", "EMAIL="))
    )
    return fields.get("NAME", ""), fields.get("EMAIL", ""), out


def test_mac_identity_wins_over_guest(
    coi_binary, workspace_dir, cleanup_containers, mac_home, guest_env
):
    _write(
        os.path.join(mac_home, ".gitconfig"),
        f"[user]\n\tname = {MAC_NAME}\n\temail = {MAC_EMAIL}\n",
    )
    name, email, out = _seeded_identity(coi_binary, workspace_dir, guest_env)
    assert (name, email) == (MAC_NAME, MAC_EMAIL), (
        f"the Mac home's identity must be seeded, not the VM's:\n{out}"
    )


def test_incomplete_mac_identity_falls_back_wholly_to_guest(
    coi_binary, workspace_dir, cleanup_containers, mac_home, guest_env
):
    _write(os.path.join(mac_home, ".gitconfig"), f"[user]\n\tname = {MAC_NAME}\n")
    name, email, out = _seeded_identity(coi_binary, workspace_dir, guest_env)
    assert (name, email) == (GUEST_NAME, GUEST_EMAIL), (
        f"a name-only Mac config must not be mixed with the guest's email:\n{out}"
    )


def test_mac_include_with_tilde_resolves_against_mac_home(
    coi_binary, workspace_dir, cleanup_containers, mac_home, guest_env
):
    _write(os.path.join(mac_home, ".gitconfig"), "[include]\n\tpath = ~/.gitconfig-coi-853\n")
    _write(
        os.path.join(mac_home, ".gitconfig-coi-853"),
        f"[user]\n\tname = {MAC_NAME}\n\temail = {MAC_EMAIL}\n",
    )
    name, email, out = _seeded_identity(coi_binary, workspace_dir, guest_env)
    assert (name, email) == (MAC_NAME, MAC_EMAIL), (
        f"~ in the Mac config's include.path must resolve against the Mac home:\n{out}"
    )
