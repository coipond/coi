"""
Test for coi file push -r - pushed entries keep their host mode and owner.

Tests that:
1. Launch a container
2. Create a local tree with a 0700 dir, a 0664 file and a 0755 script
3. Push it with -r, under its own name and under another name
4. Verify each entry in the container has the host mode, UID and GID
"""

import os
import subprocess
import time

from support.helpers import calculate_container_name


def test_push_directory_preserves_permissions(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that every entry of a recursively pushed directory keeps the mode,
    UID and GID it has on the host. The 0664 file shows the mode is not
    masked by the umask.

    Flow:
    1. Launch a container
    2. Create the local tree with explicit modes
    3. Push it to the same name and to a new name (staged on the host)
    4. Verify mode/UID/GID of each entry with stat
    5. Cleanup
    """
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container ===

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    # === Phase 2: Create local tree with explicit modes ===

    tree = os.path.join(workspace_dir, "push-perm-dir")
    private = os.path.join(tree, "private")
    os.makedirs(private, exist_ok=True)
    entries = {
        "shared.txt": 0o664,
        "run.sh": 0o755,
        "private/secret.txt": 0o600,
    }
    for rel, mode in entries.items():
        local = os.path.join(tree, rel)
        with open(local, "w") as f:
            f.write(f"{rel}\n")
        os.chmod(local, mode)
    os.chmod(private, 0o700)
    os.chmod(tree, 0o755)

    expected = {}
    for rel in ["", "private", *entries]:
        st = os.stat(os.path.join(tree, rel))
        expected[rel] = f"{st.st_mode & 0o777:o} {st.st_uid} {st.st_gid}"

    # === Phase 3: Push under the same name and under another name ===

    for target in ["/root/push-perm-dir", "/root/push-perm-renamed"]:
        result = subprocess.run(
            [coi_binary, "file", "push", "-r", tree, f"{container_name}:{target}"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, f"Push to {target} should succeed. stderr: {result.stderr}"

    # === Phase 4: Verify mode and owner of every entry ===

    for target in ["/root/push-perm-dir", "/root/push-perm-renamed"]:
        for rel, want in expected.items():
            remote = f"{target}/{rel}" if rel else target
            result = subprocess.run(
                [
                    coi_binary,
                    "container",
                    "exec",
                    container_name,
                    "--",
                    "stat",
                    "-c",
                    "%a %u %g",
                    remote,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode == 0, f"stat {remote} should succeed. stderr: {result.stderr}"
            combined_output = result.stdout + result.stderr
            assert want in combined_output, (
                f"{remote} should keep host mode/UID/GID '{want}', got:\n{combined_output}"
            )

    # === Phase 5: Cleanup ===

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
