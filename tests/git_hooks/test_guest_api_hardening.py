"""Test that the Incus guest API is disabled inside Coi containers.

The Incus guest API (/dev/incus) exposes the full device topology including
host source paths (username, workspace location, which paths are RO-protected).
This is a reconnaissance aid for mount namespace bypass attacks.

Coi does NOT use the guest agent internally — it communicates with containers
via the host admin socket. Disabling the guest API has zero impact on Coi
functionality.

See FLAWS.md Finding 3.
"""

import subprocess


class TestGuestAPIHardening:
    """Verify that /dev/incus is not accessible inside Coi containers."""

    def test_dev_incus_not_accessible(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that /dev/incus does not exist inside the container.

        When security.guestapi=false, Incus does not create the /dev/incus
        device inside the container at all.
        """
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                "ls /dev/incus/ 2>&1 || echo NO_DEV_INCUS",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0, (
            f"'coi run' failed before /dev/incus could be checked. "
            f"Return code: {result.returncode}. "
            f"Stdout: {result.stdout} Stderr: {result.stderr}"
        )

        combined = result.stdout + result.stderr
        # /dev/incus should not exist — either ls fails or we get our marker
        assert (
            "NO_DEV_INCUS" in combined or "No such file" in combined or "cannot access" in combined
        ), (
            f"FLAWS Finding 3: /dev/incus appears to be accessible inside the container. "
            f"Output: {combined}"
        )

    def test_guest_api_socket_not_available(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that the guest API socket is not reachable.

        Even if /dev/incus somehow existed, the socket should not respond.
        """
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                "curl -s --unix-socket /dev/incus/sock http://_/1.0 2>&1 || echo SOCKET_UNAVAILABLE",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0, (
            f"'coi run' failed before guest API socket could be checked. "
            f"Return code: {result.returncode}. "
            f"Stdout: {result.stdout} Stderr: {result.stderr}"
        )

        combined = result.stdout + result.stderr
        # The socket should not be available
        assert (
            "SOCKET_UNAVAILABLE" in combined
            or "No such file" in combined
            or "Connection refused" in combined
            or "Couldn't connect" in combined
            or "cannot access" in combined
        ), (
            f"FLAWS Finding 3: Guest API socket appears reachable inside the container. "
            f"Output: {combined}"
        )

    def test_no_host_path_leak(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that host source paths are not leaked via the device topology API.

        This is the specific attack from FLAWS.md Finding 3: querying
        /1.0/devices returns host source paths including username and
        workspace location.
        """
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                "curl -s --unix-socket /dev/incus/sock http://_/1.0/devices 2>&1 || echo GUEST_API_BLOCKED",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0, (
            f"'coi run' failed before device topology could be checked. "
            f"Return code: {result.returncode}. "
            f"Stdout: {result.stdout} Stderr: {result.stderr}"
        )

        # Only check stdout (the in-container command output). stderr contains
        # Coi's own setup logs which naturally reference the workspace path.
        cmd_output = result.stdout

        # The guest API should be blocked entirely — verify we got the expected
        # failure marker or a connection error, not a successful JSON response
        assert (
            "GUEST_API_BLOCKED" in cmd_output
            or "No such file" in cmd_output
            or "Connection refused" in cmd_output
            or "Couldn't connect" in cmd_output
            or "cannot access" in cmd_output
        ), f"FLAWS Finding 3: Guest API /devices endpoint appears reachable. Output: {cmd_output}"

        # Defense-in-depth: even if the above assertion somehow passed with
        # unexpected output, the workspace source path must never appear
        # in the command output (it would indicate the device topology leaked)
        assert workspace_dir not in cmd_output, (
            f"FLAWS Finding 3: Host workspace path leaked via guest API device topology. "
            f"Workspace path '{workspace_dir}' found in output: {cmd_output}"
        )
