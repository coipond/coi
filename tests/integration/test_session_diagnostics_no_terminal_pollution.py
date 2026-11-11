"""
Integration tests: session-runtime diagnostics must never reach the terminal.

Regression tests for the issue #372 class. During an interactive `coi shell`
session the security monitors and the runtime-limit watchdog run as background
goroutines in the same process that is interactively attached to the container's
tmux — so the process's os.Stdout/os.Stderr ARE the user's terminal. Any
diagnostic written there corrupts the AI tool's TUI. These tests lock the
behaviour for two of those runtime components:

  1. the nft monitor's COI_NFT_DEBUG output goes to the session log, not the
     terminal;
  2. the runtime-limit (max_duration) watchdog stops the container without
     polluting the attached terminal.

The responder's auto-kill cleanup warnings and the nft debugf routing are also
locked deterministically by Go unit tests (internal/monitor, internal/nftmonitor).
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path

import pexpect
import pytest

from support.helpers import (
    TerminalEmulator,
    calculate_container_name,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
)


def _stdout_log(container_name):
    return os.path.expanduser(f"~/.coi/logs/{container_name}.stdout.log")


def _raw_terminal(child):
    assert isinstance(child.logfile_read, TerminalEmulator), (
        f"expected TerminalEmulator capture, got {type(child.logfile_read)!r}"
    )
    raw = child.logfile_read.get_raw_output()
    assert raw, "terminal capture is empty — the no-leak assertion would be vacuous"
    return raw


def _shutdown(child):
    if child is None:
        return
    try:
        child.sendline("exit")
        time.sleep(0.3)
        child.sendline("sudo poweroff")
        time.sleep(1)
    except Exception:
        pass
    try:
        child.close(force=True)
    except Exception:
        pass


@pytest.fixture(scope="module")
def nft_monitoring_available():
    """Skip nft-monitor tests where nft/journal access is unavailable (e.g. CI
    runners without systemd journal)."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "nft", "list", "ruleset"], capture_output=True, timeout=10
        )
        if result.returncode != 0:
            pytest.skip("NFT not available: nft command failed (check sudo permissions)")
    except subprocess.TimeoutExpired:
        pytest.skip("NFT not available: nft command timed out")
    except FileNotFoundError:
        pytest.skip("NFT not available: nft command not found")

    try:
        result = subprocess.run(["journalctl", "-n", "1", "-k"], capture_output=True, timeout=5)
        if result.returncode != 0:
            pytest.skip("NFT monitoring not available: journal access failed")
    except subprocess.TimeoutExpired:
        pytest.skip("NFT monitoring not available: journal access timed out")
    except FileNotFoundError:
        pytest.skip("NFT monitoring not available: journalctl not found")

    return True


def test_nft_debug_diagnostics_go_to_log_not_terminal(
    coi_binary, workspace_dir, cleanup_containers, nft_monitoring_available
):
    """With COI_NFT_DEBUG=1 the nft monitor emits [NFT-DEBUG] lines from its
    daemon goroutines; they must land in the session log, never the attached
    terminal."""
    config = """
[monitoring]
enabled = true

[monitoring.nft]
enabled = true
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(config)
        config_file = f.name

    child = None
    try:
        env = {"COI_USE_DUMMY": "1", "COI_CONFIG": config_file, "COI_NFT_DEBUG": "1"}
        child = spawn_coi(
            coi_binary,
            ["shell", "--workspace", workspace_dir, "--slot", "1"],
            cwd=workspace_dir,
            env=env,
            timeout=240,
        )
        wait_for_container_ready(child, timeout=90)
        wait_for_prompt(child, timeout=120)

        container_name = calculate_container_name(workspace_dir, 1)
        log_path = _stdout_log(container_name)

        # The nft daemon starts during startMonitoringPhase (before the attach),
        # so its first debug lines ("Daemon.processEvents started", etc.) are
        # emitted almost immediately. Drain the terminal while waiting for them
        # to appear in the log so a leak onto the terminal would be captured.
        logged = False
        post_drain_until = None
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                child.read_nonblocking(size=4096, timeout=3)
            except pexpect.TIMEOUT:
                pass
            except pexpect.EOF:
                break

            if (
                not logged
                and os.path.exists(log_path)
                and "[NFT-DEBUG]" in Path(log_path).read_text()
            ):
                logged = True
                post_drain_until = time.time() + 8

            if logged and time.time() >= post_drain_until:
                break

        raw = _raw_terminal(child)
        assert "[NFT-DEBUG]" not in raw, (
            f"nft debug output leaked onto the attached terminal (issue #372).\n{raw}"
        )
        assert logged, (
            "nft debug output never reached the session log — the nft daemon may "
            f"not have started.\nlog:\n"
            f"{Path(log_path).read_text() if os.path.exists(log_path) else '(no log)'}"
        )
    finally:
        _shutdown(child)
        os.unlink(config_file)


def test_shell_runtime_limit_stop_does_not_pollute_terminal(
    coi_binary, workspace_dir, cleanup_containers
):
    """When the max_duration watchdog stops the container mid-session, its
    diagnostics and the incus stop subprocess output must go to the session log,
    not the attached terminal. (Existing limits tests cover only `coi run`; the
    interactive shell path — where os.Stderr is the user's TUI — was untested.)"""
    # The watchdog timer starts during session setup, so max_duration must
    # comfortably exceed worst-case container-ready + prompt-render time under CI
    # load — otherwise the container is stopped before the prompt appears and the
    # test errors during setup rather than exercising the no-leak path.
    config = """
[limits.runtime]
max_duration = "40s"
auto_stop = true
stop_graceful = false
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(config)
        config_file = f.name

    child = None
    try:
        env = {"COI_USE_DUMMY": "1", "COI_CONFIG": config_file}
        child = spawn_coi(
            coi_binary,
            ["shell", "--workspace", workspace_dir, "--slot", "1"],
            cwd=workspace_dir,
            env=env,
            timeout=240,
        )
        wait_for_container_ready(child, timeout=90)
        wait_for_prompt(child, timeout=120)

        container_name = calculate_container_name(workspace_dir, 1)
        log_path = _stdout_log(container_name)

        # Drain the terminal until the watchdog fires and stops the container
        # (the session ends, or the log records the stop).
        stopped = False
        post_drain_until = None
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                child.read_nonblocking(size=4096, timeout=3)
            except pexpect.TIMEOUT:
                pass
            except pexpect.EOF:
                stopped = True
                break

            if (
                not stopped
                and os.path.exists(log_path)
                and "Container stopped due to runtime limit" in Path(log_path).read_text()
            ):
                stopped = True
                post_drain_until = time.time() + 8

            if stopped and post_drain_until is not None and time.time() >= post_drain_until:
                break

        raw = _raw_terminal(child)
        # The watchdog's [limits] diagnostics and any incus stop subprocess output
        # must not reach the terminal.
        for pat in ("[limits]", "Runtime limit reached", "Container stopped due to runtime limit"):
            assert pat not in raw, (
                f"runtime-limit diagnostic {pat!r} leaked onto the terminal (issue #372).\n{raw}"
            )

        assert stopped, (
            "runtime-limit watchdog did not stop the container within the window.\nlog:\n"
            f"{Path(log_path).read_text() if os.path.exists(log_path) else '(no log)'}"
        )
        log = Path(log_path).read_text()
        assert "[limits]" in log, f"runtime-limit diagnostics not routed to session log:\n{log}"
    finally:
        _shutdown(child)
        os.unlink(config_file)
