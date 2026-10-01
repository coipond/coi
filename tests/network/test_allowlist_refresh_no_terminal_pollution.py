"""
Integration tests: allowlist network diagnostics must never reach the terminal.

Regression tests for https://github.com/coipond/coi/issues/372.

In allowlist mode coi resolves the allowed domains at setup and a background
goroutine periodically re-resolves them (TTL-aware) and updates the nft rules.
Before the fix, the resolver and nft helpers logged via the global `log` package
(stderr), which in a running `coi shell` is the user's tmux terminal — so every
refresh dumped lines like `example.com: resolved 3 IPs (TTL: 300s)` straight into
the Claude session. (An earlier fix only redirected the refresh goroutine's own
"IP refresh: ..." lines, so the resolver flood persisted in 0.9.)

These tests lock the *behaviour*, not the code:
  1. setup-time network diagnostics do not appear in the terminal, and ARE
     written to the session log files (~/.coi/logs/<container>.{stdout,stderr}.log);
  2. a real background refresh fires in a live session and its output goes to the
     log file, NOT the attached terminal.
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path

import pexpect

from support.helpers import (
    TerminalEmulator,
    calculate_container_name,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
)

# Substrings emitted only by the network resolver / IP-refresh diagnostics.
# None of these must ever appear on the user's terminal. They are specific
# enough not to collide with the normal "[setup] ..." progress output.
LEAK_PATTERNS = [
    "IP refresh:",  # refresh goroutine progress
    "(TTL:",  # resolver: "<domain>: resolved N IPs (TTL: Xs)"
    ": resolved ",  # resolver per-domain resolution line
    "TTL-aware DNS",  # resolver fallback notice
    "Using cached IPs for",  # resolver cache notice
    "No cached IPs available",
    "updating nft rules with",
    "wildcard — resolving",
    "failed to resolve for monitoring",  # shell.go aggregate DNS-failure warning
]

_ALLOWLIST_CONFIG = """
[network]
mode = "allowlist"
allowed_domains = [
    "8.8.8.8",
    "1.1.1.1",
    "example.com",
]
refresh_interval_minutes = 1
"""


def _assert_no_leak(text, where):
    for pat in LEAK_PATTERNS:
        assert pat not in text, (
            f"network diagnostic {pat!r} leaked into {where} (issue #372).\nOutput:\n{text}"
        )


def _session_log_path(container_name):
    return os.path.expanduser(f"~/.coi/logs/{container_name}.stdout.log")


def _session_stderr_log_path(container_name):
    return os.path.expanduser(f"~/.coi/logs/{container_name}.stderr.log")


def _read_both_logs(container_name):
    """Return (stdout_log, stderr_log) contents, '' for any not yet created."""
    out_path = _session_log_path(container_name)
    err_path = _session_stderr_log_path(container_name)
    out = Path(out_path).read_text() if os.path.exists(out_path) else ""
    err = Path(err_path).read_text() if os.path.exists(err_path) else ""
    return out, err


def _container_name_from_output(output):
    for line in output.split("\n"):
        if "Container:" in line or "Container name:" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return None


def test_setup_diagnostics_not_in_terminal_but_in_log(
    coi_binary, workspace_dir, cleanup_containers
):
    """Setup-time resolver/nft diagnostics go to the session log, not the terminal."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(_ALLOWLIST_CONFIG)
        config_file = f.name

    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file

        result = subprocess.run(
            [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        assert result.returncode == 0, f"coi shell failed: {result.stderr}"

        output = result.stdout + result.stderr
        # The bug: resolver lines leaked here. Must be clean now.
        _assert_no_leak(output, "coi shell startup terminal output")

        # Positive side: the diagnostics must actually be routed to the log files
        # (so they're not merely suppressed/lost).
        container_name = _container_name_from_output(output)
        assert container_name, f"could not find container name in:\n{output}"
        log_path = _session_log_path(container_name)
        deadline = time.time() + 20
        while not os.path.exists(log_path) and time.time() < deadline:
            time.sleep(0.5)
        assert os.path.exists(log_path), f"expected session log at {log_path}"

        out_log, err_log = _read_both_logs(container_name)
        assert "Starting IP refresh" in out_log, f"refresh setup not in session log:\n{out_log}"
        # At least one resolver line must be present in the session logs (proving
        # the resolver output is routed there, not just hidden). Success lines
        # ("resolved", "TTL:") land in the stdout log; if the host cannot resolve
        # example.com (e.g. DNS-restricted CI), the failure warning lands in the
        # stderr log instead — either one proves routing works.
        combined = out_log + err_log
        assert any(
            marker in combined
            for marker in (": resolved ", "(TTL:", "Failed to resolve", "TTL-aware DNS")
        ), (
            "resolver diagnostics not routed to session logs.\n"
            f"stdout:\n{out_log}\nstderr:\n{err_log}"
        )
    finally:
        os.unlink(config_file)


def test_background_refresh_does_not_pollute_attached_terminal(
    coi_binary, workspace_dir, cleanup_containers
):
    """A real refresh fires in a live (attached) session; its output goes to the
    log file, never the terminal.

    This exercises the timing-dependent background refresh end to end: an
    interactive `coi shell` session is kept open long enough (refresh_interval=1)
    for the refresh goroutine to fire, then we assert the terminal received none
    of the diagnostics while the log file recorded the refresh.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(_ALLOWLIST_CONFIG)
        config_file = f.name

    child = None
    try:
        env = {"COI_USE_DUMMY": "1", "COI_CONFIG": config_file}
        # Pin the workspace and slot so the container name (and therefore the log
        # path) is deterministic. Relying on the default auto-allocated slot would
        # make the computed log path wrong whenever slot 1 is already occupied
        # (lagged cleanup / a parallel session) — a false-negative trap.
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
        log_path = _session_log_path(container_name)

        # Wait for at least one background refresh to actually fire (interval=1m,
        # TTL-capped). The refresh goroutine logs this marker to the session log.
        #
        # Crucially we DRAIN the child while waiting: read_nonblocking feeds the
        # terminal emulator, so any bytes the refresh leaks onto the terminal are
        # actually captured. Without this read, leaked output would sit unread in
        # the PTY buffer and the no-leak assertion below would be vacuous.
        fired = False
        post_drain_until = None
        deadline = time.time() + 180
        while time.time() < deadline:
            try:
                child.read_nonblocking(size=4096, timeout=3)
            except pexpect.TIMEOUT:
                pass
            except pexpect.EOF:
                break

            if (
                not fired
                and os.path.exists(log_path)
                and "IP refresh: checking for updated IPs" in Path(log_path).read_text()
            ):
                fired = True
                # Keep draining briefly so the resolver/nft lines that follow the
                # refresh marker are captured too (they'd leak right after it).
                post_drain_until = time.time() + 12

            if fired and time.time() >= post_drain_until:
                break

        # Everything the attached terminal received (raw, pre-render, so nothing
        # scrolled off the 20-line emulator screen is missed). Assert the capture
        # mechanism is the one we expect and is non-empty, so a capture failure
        # fails loudly instead of silently passing the no-leak check.
        assert isinstance(child.logfile_read, TerminalEmulator), (
            f"expected TerminalEmulator capture, got {type(child.logfile_read)!r}; "
            "cannot validate terminal cleanliness"
        )
        raw = child.logfile_read.get_raw_output()
        assert raw, "terminal capture is empty — the no-leak assertion would be vacuous"

        _assert_no_leak(raw, "attached coi shell terminal during a refresh")

        assert fired, (
            "background IP refresh did not fire within 180s, so the no-leak "
            f"assertion could not be validated against a real refresh.\nlog:\n"
            f"{Path(log_path).read_text() if os.path.exists(log_path) else '(no log)'}"
        )
        # The refresh's diagnostics must be in the log (routed, not lost).
        log = Path(log_path).read_text()
        assert "IP refresh:" in log, f"refresh output not routed to session log:\n{log}"
    finally:
        if child is not None:
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
        os.unlink(config_file)


def test_run_allowlist_does_not_leak_resolver_output(coi_binary, workspace_dir, cleanup_containers):
    """`coi run` silences network output via a discard logger; the resolver must
    honour it and not leak diagnostics to the terminal.

    `coi run` (and the configure path) construct the network Manager with a
    discard logger to suppress network output — but the resolver/nft helpers log
    via the package logger, which was only wired up for `coi shell`. So in
    allowlist mode `coi run` dumped resolver lines (`example.com: resolved 3 IPs
    (TTL: 300s)`) to stderr despite the explicit discard request — the same leak
    class as issue #372 on a different command. This locks the discard behaviour:
    a successful allowlist `coi run` (which necessarily resolves the allowed
    domains to build the nft rules) must leave the terminal free of resolver
    diagnostics.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(_ALLOWLIST_CONFIG)
        config_file = f.name

    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file

        result = subprocess.run(
            [coi_binary, "run", "--workspace", workspace_dir, "echo", "coi-run-ok"],
            capture_output=True,
            text=True,
            timeout=240,
            env=env,
        )
        # A successful run means allowlist setup ran, i.e. the resolver actually
        # resolved the allowed domains — so the no-leak check below is validated
        # against real resolver activity, not a no-op.
        assert result.returncode == 0, (
            f"coi run failed (rc={result.returncode}):\nstdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
        assert "coi-run-ok" in result.stdout, (
            f"command did not run as expected:\nstdout:\n{result.stdout}"
        )
        # The discard logger must have suppressed the resolver diagnostics: none
        # may reach stdout/stderr. (The intentional one-shot "Network isolation
        # applied: allowlist" status line is not a resolver diagnostic and is
        # deliberately not in LEAK_PATTERNS.)
        _assert_no_leak(result.stdout + result.stderr, "coi run output (allowlist mode)")
    finally:
        os.unlink(config_file)
