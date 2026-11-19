"""
Tests for the goose install in build.sh.

install_goose downloads the pinned goose release tarball for the host CPU
(x86_64 or aarch64), checks its sha256 before unpacking, installs
/usr/local/bin/goose and writes /etc/goose/config.yaml. These tests source the
real function from build.sh with curl, uname and sleep faked via PATH, the
install paths moved under tmp_path and the pinned sha256 values replaced by
the fake tarball's. Hermetic: no network, no root, no Incus.
"""

import hashlib
import io
import os
import re
import subprocess
import tarfile
from pathlib import Path

BUILD_SH = Path(__file__).resolve().parents[2] / "profiles" / "default" / "build.sh"

# Sources the GOOSE_* constants, log and install_goose from build.sh, sets the
# pinned sha256 values to $TEST_SHA256_<ARCH> and runs the installer with the install
# paths moved under $TEST_ROOT. tar logs each call to $TAR_LOG.
_RUN_INSTALL = r"""
set -euo pipefail
source <(grep -E '^GOOSE_(VERSION|SHA256_[A-Z0-9_]+)=' "$BUILD_SH")
GOOSE_SHA256_X86_64="$TEST_SHA256_X86_64"
GOOSE_SHA256_AARCH64="$TEST_SHA256_AARCH64"
source <(sed -n '/^log()/,/^}/p' "$BUILD_SH")
source <(sed -n '/^install_goose()/,/^}/p' "$BUILD_SH" |
    sed -e "s|/usr/local/bin|$TEST_ROOT/bin|g" -e "s|/etc/goose|$TEST_ROOT/etc/goose|g")
tar() { echo "$*" >> "$TAR_LOG"; command tar "$@"; }
install_goose
"""

GOOSE_BINARY = b"#!/bin/sh\necho goose 1.57.0-fake\n"

# The pin variable install_goose must check for each `uname -m`; the other
# arch's pin is set to OTHER_ARCH_SHA256 so a swapped pin fails the install.
PIN_VARS = {
    "x86_64": "TEST_SHA256_X86_64",
    "aarch64": "TEST_SHA256_AARCH64",
    "arm64": "TEST_SHA256_AARCH64",
}
OTHER_ARCH_SHA256 = "f" * 64


def _goose_version():
    values = re.findall(r'^GOOSE_VERSION="([^"]+)"', BUILD_SH.read_text(), re.MULTILINE)
    assert len(values) == 1, f"expected one GOOSE_VERSION, got {values}"
    return values[0]


def _run_install(tmp_path, machine, sha256=None):
    """Run install_goose on a host whose `uname -m` is `machine`. The pin of
    that arch is set to `sha256` (None: the fake tarball's real sha256).
    Returns (result, requested URLs, tar calls)."""
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    (tmp_path / "bin").mkdir()

    tarball = tmp_path / "goose.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        info = tarfile.TarInfo("./goose")
        info.size = len(GOOSE_BINARY)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(GOOSE_BINARY))

    curl_log = tmp_path / "curl.log"
    tar_log = tmp_path / "tar.log"
    scripts = {
        "curl": (
            "#!/bin/sh\n"
            'out=""\n'
            "while [ $# -gt 0 ]; do\n"
            '    case "$1" in\n'
            '        -o) out="$2"; shift ;;\n'
            f'        http*) echo "$1" >> {curl_log} ;;\n'
            "    esac\n"
            "    shift\n"
            "done\n"
            f'cp {tarball} "$out"\n'
        ),
        "uname": f"#!/bin/sh\necho {machine}\n",
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
        "TEST_SHA256_X86_64": OTHER_ARCH_SHA256,
        "TEST_SHA256_AARCH64": OTHER_ARCH_SHA256,
        "TMPDIR": str(tmp_path),
        "TAR_LOG": str(tar_log),
    }
    if machine in PIN_VARS:
        env[PIN_VARS[machine]] = sha256 or hashlib.sha256(tarball.read_bytes()).hexdigest()
    result = subprocess.run(
        ["bash", "-c", _RUN_INSTALL], capture_output=True, text=True, env=env, timeout=60
    )
    urls = curl_log.read_text().split() if curl_log.exists() else []
    tar_calls = tar_log.read_text().splitlines() if tar_log.exists() else []
    return result, urls, tar_calls


def test_goose_arch_map_downloads_pinned_release_asset(tmp_path):
    """Each supported `uname -m` downloads its asset from the pinned release."""
    base = f"https://github.com/aaif-goose/goose/releases/download/{_goose_version()}"
    cases = {
        "x86_64": "goose-x86_64-unknown-linux-gnu.tar.gz",
        "aarch64": "goose-aarch64-unknown-linux-gnu.tar.gz",
        "arm64": "goose-aarch64-unknown-linux-gnu.tar.gz",
    }
    for machine, asset in cases.items():
        root = tmp_path / machine
        root.mkdir()
        result, urls, _ = _run_install(root, machine)
        assert result.returncode == 0, f"{machine}: {result.stdout}{result.stderr}"
        assert urls == [f"{base}/{asset}"], f"{machine}: {urls}"


def test_goose_unsupported_arch_fails_clearly(tmp_path):
    """An unsupported CPU fails with a clear error before any download."""
    result, urls, _ = _run_install(tmp_path, "riscv64")
    assert result.returncode != 0, f"expected failure, got rc=0: {result.stdout}"
    assert "ERROR: unsupported CPU architecture 'riscv64' for goose." in result.stdout
    assert urls == []
    assert not (tmp_path / "bin" / "goose").exists()


def test_goose_sha256_mismatch_fails_before_unpack(tmp_path):
    """A tarball whose sha256 does not match the pin fails the build before
    tar runs: nothing is unpacked or installed, no config is written."""
    result, urls, tar_calls = _run_install(tmp_path, "x86_64", sha256="0" * 64)
    assert result.returncode != 0, f"expected failure, got rc=0: {result.stdout}"
    assert "ERROR: goose tarball sha256 mismatch" in result.stdout
    assert len(urls) == 1
    assert tar_calls == [], tar_calls
    assert not (tmp_path / "bin" / "goose").exists()
    assert not (tmp_path / "etc" / "goose").exists()


def test_goose_install_writes_binary_and_config(tmp_path):
    """A matching tarball installs an executable goose and writes the
    lowest-precedence config with telemetry and the keyring off."""
    result, _, tar_calls = _run_install(tmp_path, "x86_64")
    assert result.returncode == 0, f"install_goose failed: {result.stdout}{result.stderr}"
    assert len(tar_calls) == 1, tar_calls

    binary = tmp_path / "bin" / "goose"
    assert binary.read_bytes() == GOOSE_BINARY
    assert os.access(binary, os.X_OK)
    assert "goose 1.57.0-fake" in result.stdout

    config = (tmp_path / "etc" / "goose" / "config.yaml").read_text().splitlines()
    assert "GOOSE_TELEMETRY_ENABLED: false" in config
    assert "GOOSE_DISABLE_KEYRING: true" in config
