"""
The coi image must not keep a build-time apt mirror.

COI_APT_MIRROR (CI sets it) points the image build at a faster Ubuntu mirror;
it is a build speed-up, not part of the image. The build's cleanup restores
the stock apt sources and removes its backup copies, so containers from the
image use the standard Ubuntu archive. This checks the image CI actually
built (with the mirror set) from inside a real container.
"""

import os
import subprocess

SOURCES = "/etc/apt/sources.list.d/ubuntu.sources"
BACKUP_DIR = "/var/lib/coi/apt-sources-orig"


def test_image_uses_stock_apt_sources(coi_binary, cleanup_containers, workspace_dir):
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            f"cat {SOURCES}; if [ -e {BACKUP_DIR} ]; then echo BACKUP_LEFT; fi",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, f"coi run failed:\n{result.stderr}"
    out = result.stdout + result.stderr

    assert "archive.ubuntu.com/ubuntu" in out, f"expected the stock Ubuntu sources:\n{out}"
    mirror = os.environ.get("COI_APT_MIRROR", "")
    if mirror:
        assert mirror not in out, f"the image still points apt at the build mirror {mirror}:\n{out}"
    assert "azure.archive.ubuntu.com" not in out, f"the image kept a build mirror:\n{out}"
    assert "BACKUP_LEFT" not in out, f"the build's apt-sources backup was left in the image:\n{out}"
