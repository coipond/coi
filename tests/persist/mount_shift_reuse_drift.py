"""
Per-mount `shift` reuse-drift warning (#604).

[[mounts]] devices are created once and never re-added on reuse, so changing a
mount's `shift` in config is a silent no-op until the container is recreated.
Coi must WARN about that drift on reuse instead of silently ignoring it.

The effective shift depends on the container's UID-mapping regime (an idmapped
`shift` mount vs a container-wide `raw.idmap`), so the test reads the
container's raw.idmap after the first launch and adapts:

  - shift regime  (raw.idmap empty): the mount is attached shift=false; flipping
    the config to shift=true is real drift -> warning expected.
  - raw.idmap regime (raw.idmap set): a shift=true override clamps to false
    (shift and raw.idmap are mutually exclusive), so there is no drift ->
    the warning must NOT appear.

Flow: launch a persistent, named session with a trusted out-of-workspace mount
at shift=false, then relaunch the SAME container with shift=true and inspect the
reuse warning on stderr.
"""

import subprocess
import uuid

from support.helpers import calculate_container_name, write_trusted_coi_config

DRIFT_MARKER = "recreate the container (coi kill + relaunch) to apply the change"


def _config(session_name, mount_host, mount_container, shift):
    return f"""
[container]
image = "coi-default"
persistent = true
session_name = "{session_name}"

[[mounts]]
host = "{mount_host}"
container = "{mount_container}"
shift = {"true" if shift else "false"}
"""


def test_mount_shift_change_warns_on_reuse(coi_binary, tmp_path):
    session_name = f"shiftdrift-{uuid.uuid4().hex[:8]}"
    # session_name keys the identity, so the workspace path is irrelevant here.
    container = calculate_container_name("", 1, session_name=session_name)

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "SENTINEL").write_text("x\n")
    mount_host = tmp_path / "shared"
    mount_host.mkdir()
    mount_container = "/mnt/shared-604"

    def run(shift, command):
        env = write_trusted_coi_config(
            _config(session_name, str(mount_host), mount_container, shift)
        )
        return subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                str(ws),
                "--slot",
                "1",
                "--",
                "bash",
                "-c",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=240,
            env=env,
        )

    try:
        # Run 1: create the persistent container with shift=false. The mount
        # device is attached shift=false in either UID-mapping regime, and a
        # fresh launch must not emit the reuse-drift warning.
        r1 = run(False, f"test -d {mount_container} && echo MOUNT_OK")
        assert r1.returncode == 0, f"run 1 failed. stderr: {r1.stderr}"
        assert "MOUNT_OK" in r1.stdout, (
            f"mount not present in container: {r1.stdout}\nstderr: {r1.stderr}"
        )
        assert DRIFT_MARKER not in r1.stderr, (
            f"fresh launch must not warn about mount-shift drift. stderr: {r1.stderr}"
        )

        # Which UID-mapping regime did the container land in?
        raw = subprocess.run(
            ["incus", "--project", "default", "config", "get", container, "raw.idmap"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw_idmap_active = raw.returncode == 0 and raw.stdout.strip() != ""

        # Run 2: same container, config now requests shift=true. The mount
        # device persists from creation (still shift=false) and is not re-added.
        r2 = run(True, "echo REUSED")
        assert r2.returncode == 0, f"run 2 failed. stderr: {r2.stderr}"
        assert "REUSED" in r2.stdout, (
            f"run 2 should reuse the same container: {r2.stdout}\nstderr: {r2.stderr}"
        )

        if raw_idmap_active:
            # shift=true clamps to false under raw.idmap -> the effective desire
            # still matches the attached device, so there is no real drift.
            assert DRIFT_MARKER not in r2.stderr, (
                "under raw.idmap a shift override resolves to false, so no drift "
                f"warning should appear. stderr: {r2.stderr}"
            )
        else:
            # shift regime: device is shift=false but config wants shift=true.
            assert DRIFT_MARKER in r2.stderr, (
                f"expected a mount-shift drift warning on reuse. stderr: {r2.stderr}"
            )
            assert mount_container in r2.stderr, (
                f"drift warning should name the drifted mount. stderr: {r2.stderr}"
            )
    finally:
        subprocess.run(
            ["incus", "--project", "default", "delete", container, "--force"],
            capture_output=True,
            timeout=60,
        )
