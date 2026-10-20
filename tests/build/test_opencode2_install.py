"""
Tests for the opencode2 (OpenCode v2) install in build.sh.

OpenCode v2 has no GitHub release assets: it ships as the npm package
@opencode/cli-linux-<arch>. install_opencode2 picks the newest stable 2.x from
the npm registry, falls back to OPENCODE2_FALLBACK_VERSION, and installs into
its own directory so the v1 `opencode` install is untouched. These tests source
the real functions from build.sh with curl faked via PATH and the install paths
moved under tmp_path. Hermetic: no network, no Incus.
"""

import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

BUILD_SH = Path(__file__).resolve().parents[2] / "profiles" / "default" / "build.sh"

# Sources the fallback version, log, the arch helper and install_opencode2 from
# build.sh, and runs the installer with the install paths moved under
# $TEST_ROOT. curl and sleep are faked via PATH; chown is a no-op.
_RUN_INSTALL = r"""
set -euo pipefail
CODE_USER=code
chown() { :; }
source <(grep '^OPENCODE2_FALLBACK_VERSION=' "$BUILD_SH")
for fn in log opencode_asset_arch opencode2_npm_version; do
    source <(sed -n "/^${fn}()/,/^}/p" "$BUILD_SH")
done
source <(sed -n '/^install_opencode2()/,/^}/p' "$BUILD_SH" |
    sed -e "s|/home/\$CODE_USER|$TEST_ROOT/home|g" -e "s|/usr/local/bin|$TEST_ROOT/bin|g")
install_opencode2
"""


def _fallback_version():
    versions = re.findall(
        r'^OPENCODE2_FALLBACK_VERSION="([^"]+)"', BUILD_SH.read_text(), re.MULTILINE
    )
    assert len(versions) == 1, f"expected one OPENCODE2_FALLBACK_VERSION, got {versions}"
    return versions[0]


def _run_install(tmp_path, versions, downloadable):
    """Run install_opencode2 with `versions` listed on the registry (None: the
    lookup fails); only the versions in `downloadable` have a tarball.
    Returns (result, the versions whose tarball was requested)."""
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    (tmp_path / "bin").mkdir()

    binary = b"#!/bin/sh\necho opencode v2.0.0-fake\n"
    tarball = tmp_path / "cli.tgz"
    with tarfile.open(tarball, "w:gz") as tar:
        for name, data in (("package/package.json", b"{}"), ("package/bin/opencode", binary)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))

    doc = tmp_path / "doc.json"
    doc.write_text(json.dumps({"versions": {v: {} for v in versions or []}}))
    curl_log = tmp_path / "curl.log"
    ok_cases = " | ".join(f"*-{v}.tgz" for v in downloadable) or "__none__"
    lookup = "exit 22" if versions is None else f"cat {doc}"
    scripts = {
        "curl": (
            f'#!/bin/sh\necho "$*" >> {curl_log}\n'
            f'case "$*" in\n'
            f"    {ok_cases}) cat {tarball} ;;\n"
            f"    *.tgz) exit 22 ;;\n"
            f"    *) {lookup} ;;\n"
            f"esac\n"
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
    requested = re.findall(r"-(\d[^/\s]*)\.tgz", curl_log.read_text()) if curl_log.exists() else []
    return result, requested


def test_opencode2_fallback_version_is_v2():
    """The fallback is an explicit stable 2.x version."""
    assert re.fullmatch(r"2\.\d+\.\d+", _fallback_version())


def test_install_opencode2_picks_newest_stable_v2(tmp_path):
    """The newest stable 2.x wins: numeric order, no v1 or v3, no pre-releases.
    It lands in its own directory, linked as opencode2."""
    versions = ["1.19.3", "2.0.32", "2.1.0", "2.10.0", "2.11.0-beta.1", "3.0.0", "0.0.0-dev-1"]
    result, requested = _run_install(tmp_path, versions, ["2.10.0"])
    assert result.returncode == 0, f"install_opencode2 failed: {result.stdout}{result.stderr}"
    assert requested == ["2.10.0"], requested
    assert "WARNING" not in result.stdout + result.stderr
    installed = tmp_path / "home" / ".opencode2" / "bin" / "opencode"
    assert installed.exists()
    assert not (tmp_path / "home" / ".opencode").exists(), "must not touch the v1 directory"
    assert (tmp_path / "bin" / "opencode2").resolve() == installed.resolve()
    assert "opencode2 opencode v2.0.0-fake" in result.stdout


def test_install_opencode2_falls_back_when_lookup_fails(tmp_path):
    """A failed registry lookup does not fail the build: the fallback version
    is installed and the fallback is logged."""
    fallback = _fallback_version()
    result, requested = _run_install(tmp_path, None, [fallback])
    assert result.returncode == 0, f"install_opencode2 failed: {result.stdout}{result.stderr}"
    assert requested == [fallback], requested
    assert "WARNING: could not list opencode v2 versions" in result.stderr


def test_install_opencode2_falls_back_when_download_fails(tmp_path):
    """A resolved version without a tarball falls back after 3 attempts."""
    fallback = _fallback_version()
    result, requested = _run_install(tmp_path, [fallback, "2.99.0"], [fallback])
    assert result.returncode == 0, f"install_opencode2 failed: {result.stdout}{result.stderr}"
    assert requested == ["2.99.0"] * 3 + [fallback], requested
    assert f"WARNING: opencode2 2.99.0 download failed, falling back to {fallback}" in result.stdout


def test_install_opencode2_fails_when_nothing_downloads(tmp_path):
    """When the resolved and the fallback versions both fail, the build fails;
    a resolved version equal to the fallback is not tried twice."""
    fallback = _fallback_version()
    result, requested = _run_install(tmp_path, [fallback, "2.99.0"], [])
    assert result.returncode != 0, f"expected failure, got rc=0: {result.stdout}"
    assert requested == ["2.99.0"] * 3 + [fallback] * 3, requested
    assert "ERROR: opencode2 installation failed" in result.stdout

    (tmp_path / "same").mkdir()
    result, requested = _run_install(tmp_path / "same", [fallback], [])
    assert result.returncode != 0
    assert requested == [fallback] * 3, requested
