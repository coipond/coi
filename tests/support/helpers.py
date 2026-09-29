"""
Helper utilities for pexpect-based CLI tests.
"""

import contextlib
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from pexpect import EOF, TIMEOUT, spawn

try:
    import pyte

    HAS_PYTE = True
except ImportError:
    HAS_PYTE = False


def write_trusted_coi_config(content):
    """Write `content` to a temp TOML file and return an env dict (a copy of
    os.environ) with COI_CONFIG pointing at it, so the config is loaded in
    TRUSTED scope. Pass the result to subprocess.run(..., env=env).

    Protection-weakening toggles (security.disable_protection / protected_paths /
    host_immutable, git.writable_hooks) are honored ONLY from trusted-scope config
    (~/.coi/config.toml or $COI_CONFIG), never from an untrusted project
    .coi/config.toml — so tests that exercise those toggles must configure them
    this way. The temp file persists for the duration of the test process (it
    lives under the system temp dir, which the CI runner cleans up).
    """
    fd, path = tempfile.mkstemp(suffix=".toml", prefix="coi-trusted-")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return {**os.environ, "COI_CONFIG": path}


def write_workspace_container_config(workspace_dir, persistent=None, image=None):
    """Write [container] settings into <workspace>/.coi/config.toml.

    Replaces the removed --persistent / --image CLI flags: persistence and image
    selection are config-driven ([container] persistent / image), and both are
    honored from project scope (they are not protection-weakening fields, so
    the untrusted-config sanitizer leaves them alone).

    Appends to an existing config file if present (assumes it does not already
    contain a [container] section — TOML forbids duplicate tables).
    """
    lines = ["[container]"]
    if persistent is not None:
        lines.append(f"persistent = {'true' if persistent else 'false'}")
    if image is not None:
        lines.append(f'image = "{image}"')
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(parents=True, exist_ok=True)
    config_path = coi_dir / "config.toml"
    with open(config_path, "a") as f:
        f.write("\n" + "\n".join(lines) + "\n")
    return config_path


class TerminalEmulator:
    """
    Terminal emulator using pyte that properly handles ANSI escape sequences.

    This provides the actual rendered screen content, handling:
    - ANSI color codes
    - Cursor movements
    - Text overwrites
    - Screen clearing
    """

    def __init__(self, columns=80, lines=20, verbose=False, show_screen_updates=None):
        if not HAS_PYTE:
            raise ImportError(
                "pyte is required for terminal emulation. Install with: pip install pyte"
            )

        self.screen = pyte.Screen(columns, lines)
        self.stream = pyte.Stream(self.screen)
        self.raw_output = []
        self.verbose = verbose

        # Whether to show screen updates (defaults to verbose mode)
        if show_screen_updates is None:
            show_screen_updates = verbose
        self.show_screen_updates = show_screen_updates

        # Track last screen state to only print on changes
        self.last_screen_hash = None
        self.update_counter = 0
        self.feed_counter = 0  # Count feeds for periodic updates
        self.last_print_time = 0  # For debouncing prints

        # Debug: Show we're initialized
        if verbose:
            import sys

            sys.stderr.write(
                f"[TerminalEmulator initialized: {columns}x{lines}, verbose={verbose}, screen_updates={show_screen_updates}]\n"
            )
            sys.stderr.flush()

    def feed(self, data):
        """Feed data to the terminal emulator."""
        # DEBUG: Print that we received data
        if self.verbose and len(data) > 0:
            import sys

            sys.stderr.write(f"[FEED: {len(data)} bytes]\n")
            sys.stderr.flush()

        self.raw_output.append(data)

        # Feed to terminal emulator FIRST (so screen is updated)
        self.stream.feed(data)

        # Print raw data if verbose (after feeding to emulator)
        if self.verbose:
            print(data, end="", flush=True)

        # Show screen updates if enabled (only when screen meaningfully changes)
        if self.show_screen_updates:
            self._maybe_print_screen()

    def write(self, data):
        """Alias for feed() to match file-like interface."""
        self.feed(data)

    def flush(self):
        """No-op for file-like interface."""
        pass

    def get_display(self):
        """Get the current terminal display as a string."""
        return "\n".join(self.screen.display)

    def get_display_stripped(self):
        """Get the display with trailing whitespace removed from each line."""
        return "\n".join(line.rstrip() for line in self.screen.display)

    def get_raw_output(self):
        """Get the raw output (with ANSI codes)."""
        return "".join(self.raw_output)

    def _maybe_print_screen(self):
        """
        Print the current screen state if it has changed meaningfully.

        Uses debouncing to avoid printing too rapidly during data streaming.
        """
        import time as _time

        self.feed_counter += 1
        current_display = self.get_display_stripped()
        current_hash = hash(current_display)

        # Check if we should print
        # Only print if screen changed AND enough time passed (debounce)
        now = _time.time()
        time_since_last = now - self.last_print_time

        if current_hash != self.last_screen_hash and time_since_last >= 0.3:
            # Screen changed and debounce passed
            self.last_screen_hash = current_hash
            self.last_print_time = now
            self.update_counter += 1

            print(f"\n\n{'=' * 80}")
            print(f"SCREEN UPDATE #{self.update_counter}")
            print(f"{'=' * 80}")
            print(current_display)
            print(f"{'=' * 80}\n")
            import sys

            sys.stdout.flush()


def spawn_coi(
    binary_path,
    args,
    timeout=30,
    env=None,
    cwd=None,
    verbose=None,
    use_terminal_emulator=True,
    show_screen_updates=None,
):
    """
    Spawn a coi command with the given arguments.

    Args:
        binary_path: Path to coi binary
        args: List of arguments (e.g., ["shell", "--slot", "2"])
        timeout: Default timeout for expect operations
        env: Optional environment variables dict
        cwd: Optional working directory
        verbose: If True, print all output in real-time. If None, check COI_TEST_VERBOSE env var.
        use_terminal_emulator: If True, use pyte terminal emulator for proper ANSI handling
        show_screen_updates: If True, show rendered screen updates. If None, check COI_TEST_SHOW_SCREEN env var or defaults to verbose.

    Returns:
        pexpect.spawn object
    """
    # Build command
    cmd_args = [binary_path, *args]

    # Merge environment
    env = os.environ.copy() if env is None else {**os.environ.copy(), **env}

    # Check verbose mode - default to False now that we have LiveScreenMonitor
    if verbose is None:
        verbose = os.environ.get("COI_TEST_VERBOSE", "0") == "1"

    # Check show_screen_updates mode
    # Enable via COI_TEST_SHOW_SCREEN env var
    if show_screen_updates is None:
        show_screen_updates = os.environ.get("COI_TEST_SHOW_SCREEN", "0") == "1"

    # Spawn process
    child = spawn(
        cmd_args[0],
        cmd_args[1:],
        timeout=timeout,
        env=env,
        cwd=cwd,
        encoding="utf-8",
        dimensions=(20, 80),  # Set terminal size
    )

    # Enable logging with terminal emulator or basic capture
    if use_terminal_emulator and HAS_PYTE:
        child.logfile_read = TerminalEmulator(
            columns=80, lines=20, verbose=verbose, show_screen_updates=show_screen_updates
        )
    else:
        if use_terminal_emulator:
            print(
                "Warning: pyte not available, falling back to basic logging. Install with: pip install pyte"
            )
        child.logfile_read = LogCapture(verbose=verbose)

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"SPAWNING: {' '.join(cmd_args)}")
        print(f"CWD: {cwd}")
        if use_terminal_emulator and HAS_PYTE:
            print("MODE: Terminal Emulator (pyte)")
            if show_screen_updates:
                print("SCREEN UPDATES: Enabled (will show pyte rendered view)")
            else:
                print("SCREEN UPDATES: Disabled")
        else:
            print("MODE: Raw Capture")
        print(f"{'=' * 60}\n")
        print("--- BEGIN LIVE OUTPUT ---\n")

    return child


class LogCapture:
    """Captures output for debugging when tests fail."""

    def __init__(self, verbose=False):
        self.lines = []
        self.verbose = verbose

    def write(self, data):
        self.lines.append(data)
        # Print in real-time if verbose mode is enabled
        if self.verbose:
            print(data, end="", flush=True)

    def flush(self):
        pass

    def get_output(self):
        return "".join(self.lines)


def wait_for_prompt(child, timeout=90):
    """
    Wait for Claude's prompt to appear.
    Returns when ready for user input.

    Automatically uses terminal emulator if available, otherwise falls back to raw expect().
    """
    # Check for any valid prompt: real CLI shows "Tips for getting started", dummy shows "You:"
    prompt_patterns = ["Tips for getting started", "You:", "bypass"]

    if isinstance(child.logfile_read, TerminalEmulator):
        # Use screen-based detection - check for any prompt pattern
        try:
            wait_for_any_text_on_screen(child, prompt_patterns, timeout=timeout)
            return True
        except TimeoutError:
            display = child.logfile_read.get_display_stripped()
            raise TimeoutError(
                f"Timeout waiting for prompt.\n\nScreen display:\n{display}"
            ) from None
    else:
        # Fallback to raw expect() for non-emulator mode
        patterns = [r"Tips for getting started", r"You:", TIMEOUT]

        index = child.expect(patterns, timeout=timeout)

        if index == len(patterns) - 1:  # TIMEOUT
            output = (
                child.logfile_read.get_output() if hasattr(child.logfile_read, "get_output") else ""
            )
            raise TimeoutError(f"Timeout waiting for prompt. Output:\n{output}")

        return True


def wait_for_container_ready(child, timeout=60):
    """
    Wait for container setup messages to complete.
    Looks for "Starting session..." message (tool-agnostic).

    Automatically uses terminal emulator if available, otherwise falls back to raw expect().
    """
    if isinstance(child.logfile_read, TerminalEmulator):
        try:
            wait_for_text_on_screen(child, "Starting session", timeout=timeout)
            return True
        except TimeoutError:
            display = child.logfile_read.get_display_stripped()
            raise TimeoutError(f"Container setup timeout.\n\nScreen display:\n{display}") from None
    else:
        # Fallback to raw expect()
        try:
            child.expect(r"Starting session\.\.\.", timeout=timeout)
            return True
        except TIMEOUT:
            output = (
                child.logfile_read.get_output() if hasattr(child.logfile_read, "get_output") else ""
            )
            raise TimeoutError(f"Container setup timeout. Output:\n{output}") from None


def send_command(child, command, line_ending="\x0d", expect_response=True, timeout=60):
    """
    Send a command to Claude and optionally wait for response.

    Args:
        child: pexpect.spawn object
        command: Command string to send
        line_ending: Line ending to use. Options:
                     '\\x0d' - Ctrl+M (default, works with Claude Code)
                     '\\n'   - newline (Linux/Unix)
                     '\\r'   - carriage return
                     '\\r\\n' - both (Windows)
        expect_response: Whether to wait for a response
        timeout: Timeout for response

    Returns:
        Response text if expect_response=True, None otherwise
    """
    # Send command with line ending
    child.send(command + line_ending)

    if expect_response:
        # Wait for response (before next prompt)
        # This is tricky - we just wait a bit for output
        time.sleep(1)
        return child.before

    return None


def send_keys(child, keys):
    """
    Send keys to the terminal without Enter.

    For sending raw keystrokes. Use send_command() to send a command with Enter.

    Args:
        child: pexpect.spawn object
        keys: Keys to send (will be sent as-is)
    """
    child.send(keys)


def press_enter(child, line_ending="\x0d"):
    """
    Press Enter key in the terminal.

    Args:
        child: pexpect.spawn object
        line_ending: Line ending to use:
                     '\\x0d' - Ctrl+M (default, works with Claude Code)
                     '\\n'   - newline (Linux/Unix)
                     '\\r'   - carriage return
                     '\\r\\n' - both (Windows)
    """
    child.send(line_ending)


def send_prompt(child, prompt, delay=0.2):
    """
    Send a prompt to Claude Code with proper timing.

    Claude Code requires the prompt text and Ctrl+M to be sent separately
    with a small delay between them for proper recognition.

    Args:
        child: pexpect.spawn object
        prompt: The prompt text to send
        delay: Delay in seconds between text and Ctrl+M (default: 0.2)

    Example:
        send_prompt(child, "What is 2+2?")
        # Equivalent to:
        # child.send("What is 2+2?")
        # time.sleep(0.2)
        # child.send("\\x0d")
    """
    child.send(prompt)
    time.sleep(delay)
    child.send("\x0d")
    time.sleep(delay)


def exit_claude(child, timeout=60, use_ctrl_c=False):
    """
    Exit CLI cleanly using /exit command or Ctrl+C.

    Args:
        child: pexpect.spawn object
        timeout: How long to wait for exit (default: 60 seconds)
        use_ctrl_c: Use Ctrl+C instead of /exit (useful for persistent containers)

    Returns:
        True if CLI exited cleanly, False if timeout/force kill occurred

    Note:
        After this function returns True, child.exitstatus will be set.
        Call child.close() is done internally to wait for process termination.
    """
    # Check if we're in verbose mode
    verbose = getattr(child.logfile_read, "verbose", False)

    if verbose:
        if use_ctrl_c:
            print("\n\n--- SENDING CTRL+C (INTERRUPT) ---")
        else:
            print("\n\n--- SENDING EXIT COMMAND ---")

    if use_ctrl_c:
        # Send Ctrl+C twice to interrupt
        child.sendcontrol("c")
        time.sleep(0.5)
        child.sendcontrol("c")
        time.sleep(0.5)
    else:
        child.send("/exit")
        time.sleep(1)
        child.send("\x0d")  # Ctrl+M

    try:
        child.expect(EOF, timeout=timeout)

        # Give monitor/output time to capture cleanup messages
        # The coi process prints cleanup messages before exiting,
        # but we need to give the monitor thread time to read and display them
        time.sleep(2)

        # Wait for process to fully exit and populate exitstatus
        # This is required - expect(EOF) only means we got EOF from the process,
        # but the process may not have fully terminated yet.
        child.close(force=False)  # Wait for clean exit

        if verbose:
            print("\n--- END LIVE OUTPUT ---")
            print(f"{'=' * 60}\n")
        return True
    except TIMEOUT:
        if verbose:
            print("\n--- EXIT TIMEOUT - FORCE KILLING ---")
            print(f"{'=' * 60}\n")
        # Force kill if graceful exit fails
        child.kill(9)
        child.close(force=True)  # Force close after kill
        return False


def wait_for_specific_container_deletion(container_name, timeout=30, poll_interval=0.5):
    """
    Wait for a specific container to be deleted.

    Args:
        container_name: Exact container name to wait for
        timeout: Maximum time to wait in seconds (default: 30)
        poll_interval: How often to check in seconds (default: 0.5)

    Returns:
        True if container deleted, False if timeout
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        containers = get_container_list()
        if container_name not in containers:
            return True
        time.sleep(poll_interval)

    return False


def wait_for_container_deletion(prefix="coi-test-", timeout=30, poll_interval=0.5):
    """
    Wait for all containers matching prefix to be deleted.

    This is useful after exit_claude() to ensure the container cleanup
    completes before the monitor stops. The coi process exits quickly,
    but Incus container deletion happens asynchronously.

    Uses the same clear-screen technique as LiveScreenMonitor to provide
    a seamless visual experience.

    Args:
        prefix: Container name prefix to wait for (default: "coi-test-")
        timeout: Maximum time to wait in seconds (default: 30)
        poll_interval: How often to check in seconds (default: 0.5)

    Returns:
        True if all containers deleted, False if timeout

    Example:
        clean_exit = exit_claude(child)
        wait_for_container_deletion()  # Wait for cleanup
        assert_clean_exit(clean_exit, child)
    """
    import sys

    start_time = time.time()
    last_display = None

    while time.time() - start_time < timeout:
        containers = get_container_list()
        matching = [c for c in containers if c.startswith(prefix)]

        if len(matching) == 0:
            # All containers deleted - clear screen and show completion
            print("\033[2J\033[H", end="", file=sys.stderr)  # Clear screen
            print("✓ Container cleanup complete\n", file=sys.stderr)
            sys.stderr.flush()
            time.sleep(0.5)  # Brief pause so user can see the message
            return True

        # Build status display (like monitor does)
        elapsed = int(time.time() - start_time)
        status = f"""
Container Cleanup Status
{"=" * 40}

⏳ Waiting for container deletion...

Containers remaining: {len(matching)}
Elapsed time: {elapsed}s / {timeout}s

{chr(10).join(f"  - {c}" for c in matching)}
"""

        # Only update display if it changed (like monitor does)
        if status != last_display:
            print("\033[2J\033[H", end="", file=sys.stderr)  # Clear screen
            print(status, file=sys.stderr)
            sys.stderr.flush()
            last_display = status

        time.sleep(poll_interval)

    # Timeout - some containers still exist
    containers = get_container_list()
    matching = [c for c in containers if c.startswith(prefix)]
    if matching:
        print("\033[2J\033[H", end="", file=sys.stderr)  # Clear screen
        print(
            f"⚠️ Timeout: {len(matching)} container(s) still exist:\n{chr(10).join(f'  - {c}' for c in matching)}\n",
            file=sys.stderr,
        )
        sys.stderr.flush()

    return False


def assert_clean_exit(clean_exit, child):
    """
    Assert that Claude exited cleanly with exit code 0.

    This is a common pattern for checking successful test completion.
    Verifies both clean exit (no timeout/force kill) and zero exit status.

    Args:
        clean_exit: Boolean returned from exit_claude()
        child: pexpect.spawn object (already exited)

    Raises:
        AssertionError: If exit was not clean or exit code is not 0

    Example:
        clean_exit = exit_claude(child)
        wait_for_container_deletion()  # Optional: wait for cleanup
        assert_clean_exit(clean_exit, child)
    """
    assert clean_exit, "Claude did not exit cleanly (timeout/force kill)"
    assert child.exitstatus == 0, f"Expected exit code 0, got {child.exitstatus}"


def get_container_list():
    """
    Get list of all running containers.
    Returns list of container names.
    """
    try:
        result = subprocess.run(
            ["incus", "list", "--format=csv", "-c", "n"],
            capture_output=True,
            text=True,
            check=True,
        )
        containers = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        return containers
    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to list containers: {e}")
        return []


def cleanup_all_test_containers(pattern="coi-test-"):
    """
    Clean up all containers matching pattern.
    Default cleans coi-test-* containers ONLY (not user's active sessions).

    IMPORTANT: This should NEVER clean up containers with 'claude-' prefix
    to avoid interfering with user's active sessions.
    """
    containers = get_container_list()
    test_containers = [c for c in containers if c.startswith(pattern)]

    if not test_containers:
        print("No test containers to clean up")
        return

    print(f"Cleaning up {len(test_containers)} test containers...")

    for container in test_containers:
        try:
            subprocess.run(
                ["incus", "delete", "-f", container],
                capture_output=True,
                timeout=10,
            )
            print(f"  Deleted: {container}")
        except Exception as e:
            print(f"  Warning: Failed to delete {container}: {e}")


def get_session_id_from_output(output):
    """
    Extract session ID from coi output.
    Looks for "Session ID: <uuid>" pattern.
    """
    import re

    match = re.search(r"Session ID: ([a-f0-9\-]{36})", output)
    if match:
        return match.group(1)
    return None


def wait_for_text(child, text, timeout=30):
    """
    Wait for specific text to appear in output.
    """
    try:
        child.expect(text, timeout=timeout)
        return True
    except TIMEOUT:
        raise TimeoutError(
            f"Timeout waiting for text: {text}\nOutput:\n{child.logfile_read.get_output()}"
        ) from None


def expect_pattern(child, pattern, timeout=30):
    """
    Wait for regex pattern to match in output.
    Returns the matched text.
    """
    try:
        child.expect(pattern, timeout=timeout)
        return child.match.group(0)
    except TIMEOUT:
        raise TimeoutError(
            f"Timeout waiting for pattern: {pattern}\nOutput:\n{child.logfile_read.get_output()}"
        ) from None


def expect_and_show(child, pattern, timeout=30, description=None):
    """
    Wrapper around expect() that shows what was matched and the context.
    Useful for debugging pattern matching issues.

    Args:
        child: pexpect.spawn object
        pattern: Pattern to match (string or regex)
        timeout: Timeout in seconds
        description: Optional description of what we're looking for

    Returns:
        The index of the matched pattern (same as child.expect())
    """
    verbose = getattr(child.logfile_read, "verbose", False)

    if verbose and description:
        print(f"\n{'=' * 60}")
        print(f">>> WAITING FOR: {description}")
        print(f">>> PATTERN: {pattern}")
        print(f"{'=' * 60}\n")

    index = child.expect(pattern, timeout=timeout)

    if verbose:
        print(f"\n{'=' * 60}")
        print(">>> PATTERN MATCHED!")
        print(f"{'=' * 60}")

        # Show what was before the match (last 300 chars)
        before_text = child.before if child.before else ""
        print("\n>>> BEFORE MATCH (last 300 chars):")
        print("--- START BEFORE ---")
        print(repr(before_text[-300:]))  # Use repr to show escape sequences
        print("--- END BEFORE ---\n")

        # Show what was matched
        after_text = child.after if child.after else ""
        print(">>> MATCHED TEXT:")
        print("--- START MATCHED ---")
        print(repr(after_text))  # Use repr to show escape sequences
        print("--- END MATCHED ---\n")

        # If it's a regex match, show the actual matched group
        if child.match:
            print(f">>> MATCH OBJECT: {child.match.group(0)}")

        print(f"{'=' * 60}\n")

    return index


def wait_for_text_on_screen(child, text, timeout=30, poll_interval=0.1):
    """
    Wait for text to appear on the rendered terminal screen (not raw output).

    This function works with TerminalEmulator to check the actual displayed text,
    properly handling ANSI codes, cursor movements, etc.

    Args:
        child: pexpect.spawn object with TerminalEmulator as logfile_read
        text: Text to search for in the rendered display
        timeout: Timeout in seconds
        poll_interval: How often to check the screen (seconds)

    Returns:
        True when text is found

    Raises:
        TimeoutError: If text not found within timeout
        TypeError: If logfile_read is not a TerminalEmulator
    """
    if not isinstance(child.logfile_read, TerminalEmulator):
        raise TypeError(
            "wait_for_text_on_screen requires TerminalEmulator. Use wait_for_text for raw output."
        )

    verbose = child.logfile_read.verbose
    start_time = time.time()

    if verbose:
        print(f"\n{'=' * 60}")
        print(f">>> WAITING FOR TEXT ON SCREEN: {text}")
        print(f"{'=' * 60}\n")
        import sys

        sys.stdout.flush()

    while time.time() - start_time < timeout:
        # CRITICAL: Read from child process to trigger data flow
        # This makes pexpect read from the subprocess and feed it to our TerminalEmulator
        try:
            child.read_nonblocking(size=4096, timeout=poll_interval)
            # Data is automatically fed to logfile_read by pexpect
        except TIMEOUT:
            # No data available right now, that's okay
            pass
        except EOF:
            # Process ended
            break

        # Get the rendered screen display
        display = child.logfile_read.get_display_stripped()

        if text in display:
            if verbose:
                print(f"\n{'=' * 60}")
                print(">>> TEXT FOUND ON SCREEN!")
                print(f"{'=' * 60}")
                print("\n>>> CURRENT SCREEN DISPLAY:")
                print("--- START DISPLAY ---")
                print(display)
                print("--- END DISPLAY ---\n")
                import sys

                sys.stdout.flush()
            return True

    # Timeout - show what we did see
    display = child.logfile_read.get_display_stripped()
    error_msg = f"Timeout waiting for text on screen: {text}\n\nCurrent display:\n{display}"

    if verbose:
        print(f"\n{'=' * 60}")
        print(">>> TIMEOUT - TEXT NOT FOUND")
        print(f"{'=' * 60}")
        print("\n>>> FINAL SCREEN DISPLAY:")
        print("--- START DISPLAY ---")
        print(display)
        print("--- END DISPLAY ---\n")

    raise TimeoutError(error_msg)


def wait_for_any_text_on_screen(child, texts, timeout=30, poll_interval=0.1):
    """
    Wait for any of the given texts to appear on the rendered terminal screen.

    Args:
        child: pexpect.spawn object with TerminalEmulator as logfile_read
        texts: List of text strings to search for
        timeout: Timeout in seconds
        poll_interval: How often to check the screen (seconds)

    Returns:
        The text that was found

    Raises:
        TimeoutError: If none of the texts found within timeout
        TypeError: If logfile_read is not a TerminalEmulator
    """
    if not isinstance(child.logfile_read, TerminalEmulator):
        raise TypeError("wait_for_any_text_on_screen requires TerminalEmulator.")

    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            child.read_nonblocking(size=4096, timeout=poll_interval)
        except TIMEOUT:
            pass
        except EOF:
            break

        display = child.logfile_read.get_display_stripped()

        for text in texts:
            if text in display:
                return text

    display = child.logfile_read.get_display_stripped()
    raise TimeoutError(
        f"Timeout waiting for any of {texts} on screen.\n\nCurrent display:\n{display}"
    )


def wait_for_pattern_on_screen(child, pattern, timeout=30, poll_interval=0.1):
    """
    Wait for a regex pattern to match on the rendered terminal screen.

    Args:
        child: pexpect.spawn object with TerminalEmulator as logfile_read
        pattern: Regex pattern (compiled or string)
        timeout: Timeout in seconds
        poll_interval: How often to check the screen (seconds)

    Returns:
        Match object when pattern is found

    Raises:
        TimeoutError: If pattern not found within timeout
        TypeError: If logfile_read is not a TerminalEmulator
    """
    if not isinstance(child.logfile_read, TerminalEmulator):
        raise TypeError("wait_for_pattern_on_screen requires TerminalEmulator.")

    verbose = child.logfile_read.verbose
    start_time = time.time()

    # Compile pattern if it's a string
    if isinstance(pattern, str):
        pattern = re.compile(pattern)

    if verbose:
        print(f"\n{'=' * 60}")
        print(f">>> WAITING FOR PATTERN ON SCREEN: {pattern.pattern}")
        print(f"{'=' * 60}\n")
        import sys

        sys.stdout.flush()

    while time.time() - start_time < timeout:
        # CRITICAL: Read from child process to trigger data flow
        try:
            child.read_nonblocking(size=4096, timeout=poll_interval)
            # Data is automatically fed to logfile_read by pexpect
        except TIMEOUT:
            # No data available right now, that's okay
            pass
        except EOF:
            # Process ended
            break

        display = child.logfile_read.get_display_stripped()
        match = pattern.search(display)

        if match:
            if verbose:
                print(f"\n{'=' * 60}")
                print(">>> PATTERN MATCHED ON SCREEN!")
                print(f"{'=' * 60}")
                print(f">>> Matched text: {match.group(0)}")
                print("\n>>> CURRENT SCREEN DISPLAY:")
                print("--- START DISPLAY ---")
                print(display)
                print("--- END DISPLAY ---\n")
                import sys

                sys.stdout.flush()
            return match

    # Timeout
    display = child.logfile_read.get_display_stripped()
    error_msg = (
        f"Timeout waiting for pattern on screen: {pattern.pattern}\n\nCurrent display:\n{display}"
    )

    if verbose:
        print(f"\n{'=' * 60}")
        print(">>> TIMEOUT - PATTERN NOT FOUND")
        print(f"{'=' * 60}")
        print("\n>>> FINAL SCREEN DISPLAY:")
        print("--- START DISPLAY ---")
        print(display)
        print("--- END DISPLAY ---\n")

    raise TimeoutError(error_msg)


def refresh_screen(child, timeout=0.5, clear_buffer=False):
    """
    Force reading from child process to update the terminal emulator screen.

    This is necessary because pexpect only reads (and thus updates the terminal
    emulator) when we explicitly call read methods. After sending data, call
    this to update the screen display.

    Args:
        child: pexpect.spawn object
        timeout: How long to keep reading (in seconds)
        clear_buffer: If True, clear the pyte screen buffer before reading new data
    """
    # Clear the pyte screen buffer if requested
    if clear_buffer and isinstance(child.logfile_read, TerminalEmulator):
        child.logfile_read.screen.reset()

    # Read whatever is available with a short timeout
    # Timeout or EOF is fine - just means nothing more to read
    with contextlib.suppress(BaseException):
        child.read_nonblocking(size=65536, timeout=timeout)


class LiveScreenMonitor:
    """
    Background monitor that continuously reads from child and shows live screen updates.

    Can be used as a context manager:
        with LiveScreenMonitor(child):
            # Your test code here
            # Screen updates automatically in background

    Or manually:
        monitor = LiveScreenMonitor(child)
        monitor.start()
        # ... test code ...
        monitor.stop()
    """

    def __init__(self, child, update_interval=0.5, show_startup=True):
        self.child = child
        self.update_interval = update_interval
        self.show_startup = show_startup
        self.running = False
        self.thread = None
        self.last_display = ""

    def __enter__(self):
        """Context manager entry - start monitoring."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - stop monitoring."""
        # Don't print "Monitor stopped" message - it's confusing when
        # we're still waiting for container cleanup
        self.stop(show_message=False)
        return False  # Don't suppress exceptions

    def start(self):
        """Start the background monitor thread."""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        if self.show_startup:
            print("\n🔴 Live monitor started\n", file=sys.stderr)

    def stop(self, show_message=True):
        """Stop the background monitor thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.show_startup and show_message:
            print("\n⚫ Monitor stopped\n", file=sys.stderr)

    def get_current_screen(self):
        """Get the current screen content as a string."""
        return self.last_display

    def _monitor_loop(self):
        """Background loop that continuously reads and displays screen."""
        while self.running:
            try:
                # Read from child process
                # Timeout is fine - suppress all exceptions
                with contextlib.suppress(BaseException):
                    self.child.read_nonblocking(size=65536, timeout=0.1)

                # Get current screen
                if isinstance(self.child.logfile_read, TerminalEmulator):
                    current_display = self.child.logfile_read.get_display_stripped()

                    # Only update last_display if screen changed
                    # (screen printing is handled by TerminalEmulator._maybe_print_screen)
                    if current_display != self.last_display:
                        self.last_display = current_display

                time.sleep(self.update_interval)

            except Exception as e:
                print(f"\n⚠️ Monitor error: {e}\n", file=sys.stderr)
                break


def with_live_screen(child, update_interval=0.5):
    """
    Helper function to create a LiveScreenMonitor context manager.

    Usage in tests:
        child = spawn_coi(...)

        with with_live_screen(child):
            # Send commands and interact
            child.send('some command')
            time.sleep(2)
            # Screen updates automatically in background

    Args:
        child: pexpect.spawn object
        update_interval: How often to check for screen updates (seconds)

    Returns:
        LiveScreenMonitor context manager
    """
    return LiveScreenMonitor(child, update_interval=update_interval)


def wait_for_text_in_monitor(monitor, text, timeout=30, poll_interval=0.5):
    """
    Poll the monitor's display until text appears or timeout occurs.

    This is useful when you have a LiveScreenMonitor running and want to wait
    for specific text to appear with early exit (doesn't wait full timeout if found).

    Args:
        monitor: LiveScreenMonitor instance
        text: Text string to search for in monitor.last_display
        timeout: Maximum time to wait in seconds (default: 30)
        poll_interval: How often to check in seconds (default: 0.5)

    Returns:
        True if text found, False if timeout

    Example:
        with with_live_screen(child) as monitor:
            child.send('What is 2+2?\\x0d')
            if wait_for_text_in_monitor(monitor, '4', timeout=20):
                print("Found answer!")
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        if text in monitor.last_display:
            return True
        time.sleep(poll_interval)

    return False


def wait_for_pattern_in_monitor(monitor, pattern, timeout=30, poll_interval=0.5):
    """
    Poll the monitor's display until regex pattern matches or timeout occurs.

    Similar to wait_for_text_in_monitor but uses regex pattern matching.

    Args:
        monitor: LiveScreenMonitor instance
        pattern: Regex pattern (string or compiled) to search for
        timeout: Maximum time to wait in seconds (default: 30)
        poll_interval: How often to check in seconds (default: 0.5)

    Returns:
        Match object if found, None if timeout

    Example:
        with with_live_screen(child) as monitor:
            child.send('What is the answer?\\x0d')
            match = wait_for_pattern_in_monitor(monitor, r'\\d+', timeout=20)
            if match:
                print(f"Found number: {match.group(0)}")
    """
    if isinstance(pattern, str):
        pattern = re.compile(pattern)

    start_time = time.time()

    while time.time() - start_time < timeout:
        match = pattern.search(monitor.last_display)
        if match:
            return match
        time.sleep(poll_interval)

    return None


def wait_for_firewall_rules(container_name, timeout=30, poll_interval=0.5):
    """
    Poll nftables until the default-deny rule is active for a container.

    Queries ``sudo nft -a list chain ip coi forward`` and looks for a rule
    whose source matches the container's IP.  Returns ``True`` once the rule
    appears, or ``False`` on timeout.

    Args:
        container_name: Incus container name (used to look up the IP).
        timeout: Maximum seconds to wait (default 30).
        poll_interval: Seconds between polls (default 0.5).
    """
    # Resolve the container's IPv4 address once.
    ip_result = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if ip_result.returncode != 0:
        return False

    import json as _json

    info = _json.loads(ip_result.stdout)
    if not info:
        return False

    container_ip = None
    for addr in info[0].get("state", {}).get("network", {}).get("eth0", {}).get("addresses", []):
        if addr.get("family") == "inet":
            container_ip = addr["address"]
            break

    if not container_ip:
        return False

    # Poll for a rule referencing this container IP in the ip coi forward chain.
    # Match the IP on word boundaries (not a bare `in` substring): a substring
    # test reports a false positive when a prefix-overlapping sibling IP has a
    # rule (e.g. 10.0.0.2 spuriously matching a rule for 10.0.0.20).
    ip_re = re.compile(r"(?<![\d.])" + re.escape(container_ip) + r"(?![\d.])")
    start = time.time()
    while time.time() - start < timeout:
        result = subprocess.run(
            ["sudo", "-n", "nft", "-a", "list", "chain", "ip", "coi", "forward"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and ip_re.search(result.stdout):
            return True
        time.sleep(poll_interval)

    return False


def get_screen_display(child, refresh=False, clear_buffer=False):
    """
    Get the current rendered screen display.

    Args:
        child: pexpect.spawn object with TerminalEmulator as logfile_read
        refresh: If True, force read from child first to update screen
        clear_buffer: If True, clear the pyte screen buffer before refreshing

    Returns:
        String of the rendered terminal display

    Raises:
        TypeError: If logfile_read is not a TerminalEmulator
    """
    if refresh:
        refresh_screen(child, clear_buffer=clear_buffer)

    if isinstance(child.logfile_read, TerminalEmulator):
        return child.logfile_read.get_display_stripped()
    elif hasattr(child.logfile_read, "get_output"):
        # Fallback to raw output
        return child.logfile_read.get_output()
    else:
        return ""


def calculate_container_name(workspace_dir, slot, session_name=None):
    """
    Calculate the expected container name for a given session identity and slot.

    This replicates the identity-keyed naming logic from
    internal/session/naming.go (Identity/IdentityHash/ContainerName): the hash
    input is the workspace's absolute path, or "session-name:<name>" when a
    [container] session_name is configured.

    Args:
        workspace_dir: Path to workspace directory
        slot: Slot number
        session_name: Optional [container] session_name keying the identity

    Returns:
        Expected container name (e.g., "coi-test-85918044-1")
    """
    import hashlib

    # Get container prefix from environment (defaults to "coi-" but tests use "coi-test-")
    prefix = os.environ.get("COI_CONTAINER_PREFIX", "coi-")

    # For the path case, use os.path.abspath (not Path.resolve) to match Go's
    # filepath.Abs behavior (abspath doesn't follow symlinks, resolve does).
    identity = f"session-name:{session_name}" if session_name else os.path.abspath(workspace_dir)
    hash_bytes = hashlib.sha256(identity.encode()).digest()

    # Take first 8 hex characters
    identity_id = hash_bytes.hex()[:8]

    # Format: {prefix}{hash}-{slot}
    return f"{prefix}{identity_id}-{slot}"


def extract_container_name(result):
    """Extract the container name a `coi shell --background` launch reported.

    Complements calculate_container_name (which derives the EXPECTED name from
    workspace+slot); this reads the ACTUAL name from the launch output. Handles
    both the `--debug` line ("Container name: <n>") and the plain "Container: <n>"
    line, searching stderr then stdout. Returns the name, or None if not found.

    result: a subprocess.CompletedProcess from `coi shell --background` (text mode).
    """
    for stream in (result.stderr or "", result.stdout or ""):
        for line in stream.splitlines():
            if "Container name:" in line:
                return line.split("Container name:")[-1].strip()
            if "Container: " in line:
                return line.split("Container: ")[-1].strip()
    return None


def wait_for_container_started(coi_binary, container_name, timeout=90):
    """Poll until the container is up AND systemd's bus is reachable.

    `coi container launch` returning does not mean the guest has finished
    booting, and a bare `exec -- true` succeeding only proves the incus agent is
    up — systemd's D-Bus can still be initializing. `poweroff`/`close` talk to
    systemd over that bus, so issuing them in that window fails with
    "Failed to connect to bus".

    Gate on `systemctl is-system-running` reporting any *live* state. We
    deliberately do NOT require a fully-booted `running`/`degraded`: a Coi
    container can sit in `starting`/`initializing` for a long time under CI's
    restricted network (waiting on network units), but the systemd bus is already
    up in those states — which is all `poweroff`/`close` need. `offline` (no
    systemd), an empty reply, or a "Failed to connect to bus" stderr (bus not up
    yet) are treated as not-ready. `is-system-running` exits non-zero for several
    of these states, so the reported state *text* is what matters, not the exit
    code.
    """
    live_states = ("running", "degraded", "starting", "initializing", "maintenance")
    deadline = time.monotonic() + timeout
    last_output = "<never probed>"
    while time.monotonic() < deadline:
        running = subprocess.run(
            [coi_binary, "container", "running", container_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if running.returncode == 0:
            probe = subprocess.run(
                [
                    coi_binary,
                    "container",
                    "exec",
                    container_name,
                    "--",
                    "systemctl",
                    "is-system-running",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            # `coi container exec` surfaces the guest command's output on stderr,
            # not stdout, so inspect BOTH streams. is-system-running prints just the
            # state word (running/degraded/starting/...); "Failed to connect to bus"
            # (bus not up yet) contains no live-state token and so keeps us waiting.
            tokens = (probe.stdout + " " + probe.stderr).split()
            last_output = " ".join(tokens)[:100] or "<empty>"
            if any(state in tokens for state in live_states):
                return True
        else:
            last_output = f"not running ({(running.stderr or running.stdout).strip()[:60]})"
        time.sleep(1)
    # Surface the last observed output so a future timeout is diagnosable rather
    # than a bare "did not become ready" (pytest prints captured stdout on fail).
    print(f"wait_for_container_started({container_name}) timed out; last output: {last_output}")
    return False


def wait_for_container_stopped(coi_binary, container_name, timeout=120):
    """Poll until `coi container running` reports the container is no longer up.

    Returns (stopped, last_result). A graceful systemd shutdown runs to stock
    stop budgets (~90s) and can take longer on a loaded CI runner, so the default
    budget is generous; the last `running` CompletedProcess is returned so the
    caller can surface it in a failure message.
    """
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = subprocess.run(
            [coi_binary, "container", "running", container_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if last.returncode != 0:
            return True, last
        time.sleep(1)
    return False, last


def is_incus_permission_error(stderr):
    """Heuristic: was an incus admin operation (e.g. `incus storage create`)
    rejected because the caller does not have Incus admin access? Anything
    else (name collision, backend error, transient failure) should fail the
    test loud, not skip."""
    lowered = stderr.lower()
    return (
        "permission denied" in lowered
        or "not authorized" in lowered
        or "forbidden" in lowered
        or "access denied" in lowered
    )


def create_storage_pool(name, driver="dir"):
    """Create a storage pool for a test. Returns (ok, stderr). Callers should
    treat ok=False as a hard failure unless is_incus_permission_error(stderr),
    in which case the test should pytest.skip."""
    result = subprocess.run(
        ["incus", "storage", "create", name, driver],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode == 0, result.stderr


def delete_storage_pool(name):
    """Best-effort deletion of a test storage pool."""
    subprocess.run(
        ["incus", "storage", "delete", name],
        capture_output=True,
        timeout=30,
    )


def run_coi_in_workspace(coi_binary, workspace_dir, argv, env=None, timeout=120):
    """Run `coi run -- <argv>` from workspace_dir, capturing output.

    Shared by the protection test family (tests/mount, tests/git_hooks), which
    previously each carried an identical private copy (hoisted per the same
    convention as the storage-pool helpers, see the #684 CHANGELOG entry).
    """
    return subprocess.run(
        [coi_binary, "run", "--", *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=workspace_dir,
        env=env,
    )


def make_workspace_writable(workspace_dir):
    """Make the workspace world-writable so the container user (UID 1000) can write.

    In CI, the test runner UID (1001) differs from the container user UID (1000).
    With shift=true on the Incus disk device, host UIDs map directly — so the
    container user can only write to files with 'other' write permission. Used by
    protection tests so that ONLY a read-only mount (not file permissions) can
    stop a write, preventing false passes.
    """
    subprocess.run(["chmod", "-R", "a+rwX", workspace_dir], check=True, capture_output=True)
