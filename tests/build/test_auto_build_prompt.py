"""
Test the interactive auto-build prompt when an image is missing.

When coi shell/run is invoked from a terminal (stdin is a TTY) and the
requested image does not exist, Coi prompts the user to build it instead
of immediately failing.

Tests:
- Prompt is shown on a TTY when the default image is missing
- Answering "n" (or Enter) keeps the not-found error, process exits non-zero
- Answering "y" triggers a build attempt for the default image
- Custom image with no build config: "y" answer shows correct error
- Non-interactive path (subprocess, no PTY) still returns plain error
"""

import subprocess
from pathlib import Path

import pytest
from pexpect import EOF, TIMEOUT

from support.helpers import spawn_coi, write_workspace_container_config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_DEFAULT = "coi-prompt-test-default-missing"
_FAKE_CUSTOM = "coi-prompt-test-custom-missing"
_PROMPT_TEXT = "Build it now?"


def _get_output(child):
    """Return all captured output from a pexpect child."""
    if hasattr(child.logfile_read, "get_raw_output"):
        return child.logfile_read.get_raw_output()
    if hasattr(child.logfile_read, "get_output"):
        return child.logfile_read.get_output()
    return ""


def _close(child):
    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)


# ---------------------------------------------------------------------------
# Interactive prompt tests (pexpect provides a PTY → stdinIsTerminal() == true)
# ---------------------------------------------------------------------------


def test_prompt_shown_on_tty_for_missing_image(coi_binary, workspace_dir):
    """
    When stdin is a terminal and the image is missing, Coi should ask the
    user before failing — not immediately print an error.
    """
    write_workspace_container_config(workspace_dir, image=_FAKE_DEFAULT)
    child = spawn_coi(
        coi_binary,
        ["shell", "--workspace", workspace_dir],
        timeout=60,
        cwd=workspace_dir,
    )

    try:
        child.expect(_PROMPT_TEXT, timeout=30)
        # Prompt was shown — send "n" to decline and let the process exit
        child.sendline("n")
        child.expect(EOF, timeout=15)
    except TIMEOUT:
        output = _get_output(child)
        pytest.fail(f"Expected prompt '{_PROMPT_TEXT}' within 30s. Output:\n{output}")
    finally:
        _close(child)


def test_prompt_decline_exits_with_not_found_error(coi_binary, workspace_dir):
    """
    Answering 'n' (or just Enter) at the build prompt should exit non-zero
    with a message that still tells the user how to build.
    """
    write_workspace_container_config(workspace_dir, image=_FAKE_DEFAULT)
    child = spawn_coi(
        coi_binary,
        ["shell", "--workspace", workspace_dir],
        timeout=60,
        cwd=workspace_dir,
    )

    try:
        child.expect(_PROMPT_TEXT, timeout=30)
        child.sendline("n")
        child.expect(EOF, timeout=15)
    except TIMEOUT:
        output = _get_output(child)
        pytest.fail(f"Process did not exit cleanly after 'n'. Output:\n{output}")
    finally:
        _close(child)

    output = _get_output(child)
    assert child.exitstatus != 0 or child.signalstatus is not None, (
        f"Expected non-zero exit after declining build. Output:\n{output}"
    )
    assert "not found" in output.lower(), (
        f"Expected 'not found' in output after declining. Got:\n{output}"
    )


def test_prompt_empty_enter_treated_as_no(coi_binary, workspace_dir):
    """
    Pressing Enter without typing anything should default to 'no'.
    The process should still exit with a not-found error.
    """
    write_workspace_container_config(workspace_dir, image=_FAKE_DEFAULT)
    child = spawn_coi(
        coi_binary,
        ["shell", "--workspace", workspace_dir],
        timeout=60,
        cwd=workspace_dir,
    )

    try:
        child.expect(_PROMPT_TEXT, timeout=30)
        child.sendline("")  # just press Enter
        child.expect(EOF, timeout=15)
    except TIMEOUT:
        output = _get_output(child)
        pytest.fail(f"Process did not exit after Enter. Output:\n{output}")
    finally:
        _close(child)

    output = _get_output(child)
    assert child.exitstatus != 0 or child.signalstatus is not None, (
        f"Expected non-zero exit after pressing Enter (default No). Output:\n{output}"
    )


def test_prompt_yes_triggers_build_attempt_for_custom_image(coi_binary, workspace_dir):
    """
    Answering 'y' for a custom image with no build config should trigger the
    build path and exit with an informative error about needing a profile —
    not the generic 'image not found' message.
    """
    # Write a minimal config that declares the custom image name but provides
    # no [container.build] section — so HasBuildConfig() returns false.
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(f'[container]\nimage = "{_FAKE_CUSTOM}"\n')

    child = spawn_coi(
        coi_binary,
        ["shell", "--workspace", workspace_dir],
        timeout=60,
        cwd=workspace_dir,
    )

    try:
        child.expect(_PROMPT_TEXT, timeout=30)
        child.sendline("y")
        child.expect(EOF, timeout=30)
    except TIMEOUT:
        output = _get_output(child)
        pytest.fail(f"Process did not exit after 'y'. Output:\n{output}")
    finally:
        _close(child)

    output = _get_output(child)
    assert child.exitstatus != 0 or child.signalstatus is not None, (
        f"Expected non-zero exit (no build config). Output:\n{output}"
    )
    # Should explain that there is no build config, not just repeat "not found"
    assert (
        "container.build" in output
        or "no [container.build]" in output
        or "cannot auto-build" in output
    ), f"Expected explanation of missing build config. Got:\n{output}"


# ---------------------------------------------------------------------------
# Non-interactive path (subprocess, no PTY) — existing behaviour preserved
# ---------------------------------------------------------------------------


def test_no_prompt_when_stdin_not_tty(coi_binary, workspace_dir):
    """
    When stdin is not a TTY, Coi must not show the prompt and must fail
    immediately with the actionable error message.

    stdin=subprocess.DEVNULL guarantees a non-TTY stdin regardless of
    whether the CI runner itself has a PTY allocated.
    """
    write_workspace_container_config(workspace_dir, image=_FAKE_DEFAULT)
    result = subprocess.run(
        [
            coi_binary,
            "shell",
            "--workspace",
            workspace_dir,
            "--debug",
        ],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=30,
        cwd=workspace_dir,
    )

    assert result.returncode != 0, "Should fail when image is missing (non-interactive)"
    combined = result.stdout + result.stderr
    assert "not found" in combined.lower(), (
        f"Expected 'not found' error in non-interactive mode. Got:\n{combined}"
    )
    # The interactive prompt text must NOT appear in non-interactive output
    assert _PROMPT_TEXT not in combined, (
        f"Prompt should not appear when stdin is not a TTY. Got:\n{combined}"
    )
