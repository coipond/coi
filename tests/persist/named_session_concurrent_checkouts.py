"""
Named sessions launched from two checkouts at once: `[container] session_name`
with `persistent = true`, and a background session from checkout A still
running on slot 1.

From checkout B (different path, same name):
1. `coi shell --resume` targets A's running container (the latest session of
   the name) and must refuse: a running container cannot be remounted, and
   attaching would hand B the files of A.
2. Plain `coi shell` must not attach either. It forks the name onto slot 2 and
   warns that slot 1 is RUNNING.

The resume check runs first: once B has its own slot-2 session, that session
is the name's latest and --resume would target it instead.
"""

import subprocess
import uuid

from support.helpers import calculate_container_name, write_trusted_coi_config


def _container_exists(name):
    return (
        subprocess.run(
            ["incus", "--project", "default", "info", name],
            capture_output=True,
            timeout=60,
        ).returncode
        == 0
    )


def test_named_session_from_second_checkout_while_running(coi_binary, tmp_path):
    session_name = f"namedconc-{uuid.uuid4().hex[:8]}"
    slot1 = calculate_container_name("", 1, session_name=session_name)
    slot2 = calculate_container_name("", 2, session_name=session_name)

    ws_a = tmp_path / "checkout-a"
    ws_a.mkdir()
    ws_b = tmp_path / "checkout-b"
    ws_b.mkdir()

    env = write_trusted_coi_config(
        f"""
[container]
image = "coi-default"
persistent = true
session_name = "{session_name}"
"""
    )
    env["COI_USE_DUMMY"] = "1"

    def shell(workspace, *args):
        return subprocess.run(
            [coi_binary, "shell", "--background", *args],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )

    try:
        a = shell(ws_a)
        assert a.returncode == 0, f"session in checkout A failed. stderr: {a.stderr}"
        assert _container_exists(slot1), f"expected {slot1} after the session in A"

        resumed = shell(ws_b, "--resume")
        assert resumed.returncode != 0, (
            f"--resume from B must refuse A's running container. stderr: {resumed.stderr}"
        )
        assert "different workspace mounted" in resumed.stderr, (
            f"expected the different-workspace refusal. stderr: {resumed.stderr}"
        )
        assert "checkout-a" in resumed.stderr, (
            f"the refusal should name A's workspace. stderr: {resumed.stderr}"
        )
        assert not _container_exists(slot2), "--resume must not create a new slot"

        forked = shell(ws_b)
        assert forked.returncode == 0, f"plain shell from B failed. stderr: {forked.stderr}"
        assert f'named session "{session_name}" already has a RUNNING container on slot 1' in (
            forked.stderr
        ), f"expected the RUNNING fork warning. stderr: {forked.stderr}"
        assert "creates a NEW container (slot 2)" in forked.stderr, (
            f"the warning should name slot 2. stderr: {forked.stderr}"
        )
        assert _container_exists(slot2), f"expected {slot2} for the launch from B"
    finally:
        for name in (slot1, slot2):
            subprocess.run(
                ["incus", "--project", "default", "delete", name, "--force"],
                capture_output=True,
                timeout=60,
            )
