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

import io
import os
import re
import subprocess
import tarfile
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


# Sources install_opencode and its helpers from build.sh and runs it with the
# install paths moved under $TEST_ROOT. git, curl, sleep and chown are faked.
_RUN_INSTALL = r"""
set -euo pipefail
CODE_USER=code
chown() { :; }
source <(grep '^OPENCODE_FALLBACK_VERSION=' "$BUILD_SH")
for fn in log opencode_asset_arch opencode_v1_release_tag; do
    source <(sed -n "/^${fn}()/,/^}/p" "$BUILD_SH")
done
source <(sed -n '/^install_opencode()/,/^}/p' "$BUILD_SH" |
    sed -e "s|/home/\$CODE_USER|$TEST_ROOT/home|g" -e "s|/usr/local/bin|$TEST_ROOT/bin|g")
install_opencode
"""


def _run_install(tmp_path, tags, downloadable):
    """Run install_opencode with `tags` listed upstream; only the tags in
    `downloadable` have a release asset. Returns (result, requested URLs)."""
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    (tmp_path / "bin").mkdir()

    binary = b"#!/bin/sh\necho 1.0.0-fake\n"
    tarball = tmp_path / "opencode.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        info = tarfile.TarInfo("opencode")
        info.size = len(binary)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(binary))

    listing = "".join(f"0000000000000000000000000000000000000000\\trefs/tags/{t}\\n" for t in tags)
    curl_log = tmp_path / "curl.log"
    ok_cases = " | ".join(f"*/download/{t}/*" for t in downloadable) or "__none__"
    scripts = {
        "git": f"#!/bin/sh\nprintf '{listing}'\n",
        "curl": (
            f'#!/bin/sh\necho "$*" >> {curl_log}\n'
            f'case "$*" in\n    {ok_cases}) cat {tarball} ;;\n    *) exit 22 ;;\nesac\n'
        ),
        "sleep": "#!/bin/sh\n:\n",
    }
    for name, body in scripts.items():
        path = fake_bin / name
        path.write_text(body)
        path.chmod(0o755)

    env = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "BUILD_SH": str(BUILD_SH),
        "TEST_ROOT": str(tmp_path),
    }
    result = subprocess.run(
        ["bash", "-c", _RUN_INSTALL], capture_output=True, text=True, env=env, timeout=60
    )
    urls = curl_log.read_text().split() if curl_log.exists() else []
    return result, [u for u in urls if u.startswith("https://")]


def test_install_opencode_installs_resolved_tag(tmp_path):
    """The newest v1 tag is downloaded, with no fallback."""
    result, urls = _run_install(tmp_path, ["v1.19.3", "v1.20.0", "v2.1.0"], ["v1.20.0"])
    assert result.returncode == 0, f"install_opencode failed: {result.stdout}{result.stderr}"
    assert [u.split("/")[-2] for u in urls] == ["v1.20.0"], urls
    assert "WARNING" not in result.stdout + result.stderr
    assert (tmp_path / "home" / ".opencode" / "bin" / "opencode").exists()


def test_install_opencode_falls_back_when_resolved_download_fails(tmp_path):
    """A resolved tag without a downloadable asset falls back to the fallback
    tag after 3 attempts, and the fallback is logged."""
    fallback = _fallback_version()
    result, urls = _run_install(tmp_path, [fallback, "v1.99.0"], [fallback])
    assert result.returncode == 0, f"install_opencode failed: {result.stdout}{result.stderr}"
    assert [u.split("/")[-2] for u in urls] == ["v1.99.0"] * 3 + [fallback], urls
    assert f"WARNING: opencode v1.99.0 download failed, falling back to {fallback}" in result.stdout
    assert (tmp_path / "home" / ".opencode" / "bin" / "opencode").exists()


def test_install_opencode_fails_when_no_tag_downloads(tmp_path):
    """When the resolved and fallback tags both fail, the build fails."""
    fallback = _fallback_version()
    result, urls = _run_install(tmp_path, [fallback, "v1.99.0"], [])
    assert result.returncode != 0, f"expected failure, got rc=0: {result.stdout}"
    assert [u.split("/")[-2] for u in urls] == ["v1.99.0"] * 3 + [fallback] * 3, urls
    assert "ERROR: opencode installation failed" in result.stdout


def test_install_opencode_no_second_round_when_resolved_is_fallback(tmp_path):
    """When the resolved tag is the fallback tag, a failed download is not
    retried as a fallback."""
    fallback = _fallback_version()
    result, urls = _run_install(tmp_path, [fallback], [])
    assert result.returncode != 0, f"expected failure, got rc=0: {result.stdout}"
    assert [u.split("/")[-2] for u in urls] == [fallback] * 3, urls
    assert "falling back" not in result.stdout
