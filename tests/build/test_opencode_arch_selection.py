"""
Regression test for issue #506: opencode must be installed for the host CPU
architecture, not hardcoded to x86_64.

profiles/default/build.sh hardcoded the x64 opencode tarball, so on arm64 hosts
`opencode` failed at runtime with:
    qemu-x86_64: Could not open '/lib64/ld-linux-x86-64.so.2': No such file or directory

The install script now derives the asset from `uname -m` via the
`opencode_asset_arch` helper. These tests run that real helper (extracted from
build.sh) under a faked `uname` for each architecture, and verify the install
function builds the download URL from the detected arch rather than a hardcoded
suffix. Hermetic: no network, no Incus.
"""

import os
import re
import subprocess
from pathlib import Path

BUILD_SH = Path(__file__).resolve().parents[2] / "profiles" / "default" / "build.sh"

# Sources ONLY the opencode_asset_arch function from build.sh, then calls it, so
# we exercise the real shipped logic (not a copy). `uname` is faked via PATH.
_RUN_HELPER = r"""
set -e
source <(sed -n '/^opencode_asset_arch()/,/^}/p' "$BUILD_SH")
opencode_asset_arch
"""


def _run_for_machine(tmp_path, machine):
    fake_bin = tmp_path / machine
    fake_bin.mkdir()
    uname = fake_bin / "uname"
    uname.write_text(f"#!/bin/sh\necho {machine}\n")
    uname.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "BUILD_SH": str(BUILD_SH),
    }
    return subprocess.run(
        ["bash", "-c", _RUN_HELPER], capture_output=True, text=True, env=env, timeout=30
    )


def test_opencode_asset_arch_maps_supported_architectures(tmp_path):
    """uname -m values map to the correct opencode release asset suffix."""
    cases = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    for machine, expected in cases.items():
        result = _run_for_machine(tmp_path, machine)
        assert result.returncode == 0, f"opencode_asset_arch failed for {machine}: {result.stderr}"
        assert result.stdout.strip() == expected, (
            f"uname -m={machine}: got {result.stdout.strip()!r}, want {expected!r}"
        )


def test_opencode_asset_arch_rejects_unsupported_architecture(tmp_path):
    """An unsupported architecture exits non-zero (so the build fails loudly)."""
    result = _run_for_machine(tmp_path, "riscv64")
    assert result.returncode != 0, (
        f"expected failure for riscv64, got rc=0 stdout={result.stdout!r}"
    )


def test_install_opencode_url_uses_detected_arch():
    """The opencode download URL must be built from the detected arch, not a
    hardcoded x64 suffix (the issue #506 regression)."""
    content = BUILD_SH.read_text()
    assert "opencode_asset_arch" in content, "opencode_asset_arch helper missing"

    # Inspect the actual DOWNLOAD_URL assignment line(s), ignoring comments.
    url_lines = [ln for ln in content.splitlines() if "DOWNLOAD_URL=" in ln and "opencode" in ln]
    assert url_lines, "no opencode DOWNLOAD_URL assignment found"
    for ln in url_lines:
        assert "${OPENCODE_ARCH}" in ln, (
            f"opencode DOWNLOAD_URL is not parameterised by the detected arch: {ln.strip()}"
        )
        assert "opencode-linux-x64.tar.gz" not in ln, (
            f"opencode DOWNLOAD_URL still hardcodes the x64 asset (issue #506): {ln.strip()}"
        )


# Sources the fallback tag, log and opencode_v1_release_tag from build.sh, then
# calls the helper. `git` is faked via PATH.
_RUN_TAG_HELPER = r"""
set -euo pipefail
source <(grep '^OPENCODE_FALLBACK_VERSION=' "$BUILD_SH")
source <(sed -n '/^log()/,/^}/p' "$BUILD_SH")
source <(sed -n '/^opencode_v1_release_tag()/,/^}/p' "$BUILD_SH")
opencode_v1_release_tag
"""


def _run_tag_helper(tmp_path, git_script):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    git = fake_bin / "git"
    git.write_text(git_script)
    git.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "BUILD_SH": str(BUILD_SH),
    }
    return subprocess.run(
        ["bash", "-c", _RUN_TAG_HELPER], capture_output=True, text=True, env=env, timeout=30
    )


def _fallback_version():
    versions = re.findall(
        r'^OPENCODE_FALLBACK_VERSION="([^"]+)"', BUILD_SH.read_text(), re.MULTILINE
    )
    assert len(versions) == 1, f"expected one OPENCODE_FALLBACK_VERSION, got {versions}"
    return versions[0]


def test_opencode_fallback_version_is_v1():
    """The fallback tag is an explicit v1 release."""
    assert re.fullmatch(r"v1\.\d+\.\d+", _fallback_version())


def test_opencode_v1_release_tag_picks_newest_stable_v1(tmp_path):
    """The newest stable v1.x tag wins: numeric order, no v2, no pre-releases."""
    refs = [
        "v1.9.9",
        "v1.19.3",
        "v1.20.0",
        "v1.20.1-beta.1",
        "v2.0.32",
        "v2.1.0",
    ]
    listing = "".join(f"0000000000000000000000000000000000000000\trefs/tags/{t}\n" for t in refs)
    result = _run_tag_helper(tmp_path, f"#!/bin/sh\nprintf '{listing}'\n")
    assert result.returncode == 0, f"opencode_v1_release_tag failed: {result.stderr}"
    assert result.stdout.strip() == "v1.20.0"


def test_opencode_v1_release_tag_falls_back_when_lookup_fails(tmp_path):
    """A failed tag lookup does not fail the build: the fallback tag is used
    and the fallback is logged."""
    result = _run_tag_helper(tmp_path, "#!/bin/sh\nexit 128\n")
    assert result.returncode == 0, f"opencode_v1_release_tag failed: {result.stderr}"
    assert result.stdout.strip() == _fallback_version()
    assert "WARNING: could not list opencode v1 tags" in result.stderr


def test_opencode_v1_release_tag_falls_back_when_no_v1_tag(tmp_path):
    """A listing with no stable v1 tag gives the fallback tag."""
    listing = "0000000000000000000000000000000000000000\trefs/tags/v2.1.0\n"
    result = _run_tag_helper(tmp_path, f"#!/bin/sh\nprintf '{listing}'\n")
    assert result.returncode == 0, f"opencode_v1_release_tag failed: {result.stderr}"
    assert result.stdout.strip() == _fallback_version()


def test_install_opencode_downloads_a_release_tag():
    """The opencode download must come from a resolved release tag, not
    /latest/, so an upstream move of "latest" to v2 cannot switch majors."""
    content = BUILD_SH.read_text()
    url_lines = [ln for ln in content.splitlines() if "DOWNLOAD_URL=" in ln and "opencode" in ln]
    assert url_lines, "no opencode DOWNLOAD_URL assignment found"
    for ln in url_lines:
        assert "/releases/latest/" not in ln, f"opencode DOWNLOAD_URL follows latest: {ln.strip()}"
        assert "/releases/download/${version}/" in ln, (
            f"opencode DOWNLOAD_URL is not built from the resolved tag: {ln.strip()}"
        )
    assert 'OPENCODE_VERSION="$(opencode_v1_release_tag)"' in content, (
        "install_opencode does not resolve the tag with opencode_v1_release_tag"
    )
