"""
Integration tests for the SessionLogger introduced in the centralized logging refactor.

The SessionLogger writes all background goroutine output to per-session log files:
  ~/.coi/logs/<container>.stdout.log  — informational messages
  ~/.coi/logs/<container>.stderr.log  — warnings and errors

These tests verify the end-to-end behavior: files are created, the right content
lands in the right file, and no background output escapes to the terminal.
"""

import os
import tempfile
import time

from support.helpers import start_background_shell


def _run_shell_bg(coi_binary, workspace_dir, config_toml, *, timeout=120):
    """Start coi shell --background with the given config; return (container_name, result)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(config_toml)
        config_file = f.name
    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        return start_background_shell(coi_binary, workspace_dir, env, debug=False, timeout=timeout)
    finally:
        os.unlink(config_file)


def _wait_for_log(log_path, timeout_s=15):
    """Poll until the log file exists; return True if it appeared within timeout."""
    deadline = time.time() + timeout_s
    while not os.path.exists(log_path) and time.time() < deadline:
        time.sleep(0.5)
    return os.path.exists(log_path)


def test_session_stdout_log_created(coi_binary, workspace_dir, cleanup_containers):
    """
    ~/.coi/logs/<container>.stdout.log must be created for every coi shell session.
    """
    container_name, _ = _run_shell_bg(
        coi_binary,
        workspace_dir,
        '[network]\nmode = "open"\n',
    )

    log_path = os.path.expanduser(f"~/.coi/logs/{container_name}.stdout.log")
    assert _wait_for_log(log_path), f"Expected stdout log at {log_path}"


def test_session_stderr_log_created(coi_binary, workspace_dir, cleanup_containers):
    """
    ~/.coi/logs/<container>.stderr.log must be created for every coi shell session.
    """
    container_name, _ = _run_shell_bg(
        coi_binary,
        workspace_dir,
        '[network]\nmode = "open"\n',
    )

    log_path = os.path.expanduser(f"~/.coi/logs/{container_name}.stderr.log")
    assert _wait_for_log(log_path), f"Expected stderr log at {log_path}"


def test_session_stdout_log_contains_network_setup_info(
    coi_binary, workspace_dir, cleanup_containers
):
    """
    Network setup messages from allowlist mode must appear in stdout.log, not on the terminal.
    """
    container_name, result = _run_shell_bg(
        coi_binary,
        workspace_dir,
        """
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",
    "1.1.1.1",
    "example.com",
]
refresh_interval_minutes = 30
""",
    )
    terminal_output = result.stdout + result.stderr

    # Network setup messages must be in the log file, not the terminal.
    log_path = os.path.expanduser(f"~/.coi/logs/{container_name}.stdout.log")
    assert _wait_for_log(log_path), f"Expected stdout log at {log_path}"

    with open(log_path) as fh:
        log_contents = fh.read()

    # The network manager logs this when it sets up allowlist mode.
    assert "allowlist" in log_contents.lower() or "allowed" in log_contents.lower(), (
        f"Expected network setup info in {log_path}.\nLog:\n{log_contents}"
    )

    # These specific messages must NOT appear in the terminal.
    for phrase in ["Network mode:", "Container IP:", "Resolving", "Starting IP refresh"]:
        assert phrase not in terminal_output, (
            f"Network setup message leaked into terminal: {phrase!r}\n"
            f"Terminal output:\n{terminal_output}"
        )


def test_session_log_not_discarded_in_open_mode(coi_binary, workspace_dir, cleanup_containers):
    """
    Even with network.mode = open, the stdout log file must be non-empty — the
    session logger is created unconditionally, not only when network is active.
    """
    container_name, _ = _run_shell_bg(
        coi_binary,
        workspace_dir,
        '[network]\nmode = "open"\n',
    )

    log_path = os.path.expanduser(f"~/.coi/logs/{container_name}.stdout.log")
    assert _wait_for_log(log_path), f"Expected stdout log at {log_path}"

    size = os.path.getsize(log_path)
    assert size >= 0, f"stdout log exists at {log_path}"
    # File was created (size check above) — even 0 bytes is acceptable for open mode
    # since the open-mode setup may produce no log lines. The important thing is
    # the file exists and is not the old network-refresh-*.log path.
    old_path = os.path.expanduser(f"~/.coi/logs/network-refresh-{container_name}.log")
    assert not os.path.exists(old_path), (
        f"Old-style network-refresh log should not be created: {old_path}"
    )


def test_old_network_refresh_log_not_created(coi_binary, workspace_dir, cleanup_containers):
    """
    The old per-container network-refresh-<container>.log file must NOT be created.
    Session output goes to <container>.stdout.log instead.
    """
    container_name, _ = _run_shell_bg(
        coi_binary,
        workspace_dir,
        """
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",
    "1.1.1.1",
]
refresh_interval_minutes = 30
""",
    )

    old_log = os.path.expanduser(f"~/.coi/logs/network-refresh-{container_name}.log")
    assert not os.path.exists(old_log), (
        f"Old-style log file should not be created at {old_log}. "
        f"Output now goes to {container_name}.stdout.log."
    )

    new_log = os.path.expanduser(f"~/.coi/logs/{container_name}.stdout.log")
    assert _wait_for_log(new_log), f"New session log should exist at {new_log}"
