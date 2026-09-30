"""
Behavioral test for tmux escape-time in the coi-default image.

Regression for https://github.com/coipond/coi/issues/378:
When using nested tmux (e.g. SSH → host tmux → Coi tmux), the default
escape-time of 500ms stacks at each nesting level, causing the Escape key to
feel completely broken in applications like opencode/vim.

The fix ships `/etc/tmux.conf` with `set -g escape-time 10` so the Escape key
is delivered to applications promptly even in nested setups.

Tests that:
1. /etc/tmux.conf declares escape-time 10.
2. The Escape key actually passes through nested tmux within 200ms — a
   behavioral end-to-end check that would fail at the 500ms default because
   the inner tmux would not have flushed the byte to the application yet.
"""

import subprocess
import time

from support.helpers import calculate_container_name


def test_tmux_escape_time_config(coi_binary, cleanup_containers, workspace_dir):
    """
    /etc/tmux.conf must declare escape-time 10.
    """
    container_name = calculate_container_name(workspace_dir, 1)

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch failed. stderr: {result.stderr}"

    time.sleep(3)

    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "cat",
            "/etc/tmux.conf",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"/etc/tmux.conf must exist. stderr: {result.stderr}"
    combined = result.stdout + result.stderr
    assert "set -g escape-time 10" in combined, (
        f"/etc/tmux.conf must set escape-time to 10. Got:\n{combined}"
    )

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )


def test_esc_passes_through_nested_tmux_quickly(coi_binary, cleanup_containers, workspace_dir):
    """
    Escape key sent to an outer tmux must arrive in the inner tmux application
    within 200ms — a timing window that fails at the 500ms default.

    Setup inside the container:
      outer-tmux → attaches to → inner-tmux → cat (writes stdin to file)

    We send Escape to the outer pane, sleep 200ms, then check whether
    /tmp/esc_recv contains byte 0x1b. With escape-time=10 the byte arrives in
    ~10ms; with the default 500ms it would not have arrived yet.
    """
    # This test script runs entirely inside the container via `coi run`.
    # It creates a nested tmux scenario and measures Esc delivery latency.
    test_script = r"""
set -e

cleanup() {
    tmux kill-server 2>/dev/null || true
}
trap cleanup EXIT

# Start inner tmux with a cat listener writing to a file.
tmux new-session -d -s inner -x 200 -y 50
tmux send-keys -t inner 'stdbuf -o0 cat > /tmp/esc_recv' Enter
sleep 0.3

# Start outer tmux and attach it to the inner session.
# This replicates the nested-tmux scenario: outer pane → inner tmux terminal.
tmux new-session -d -s outer -x 200 -y 50
tmux send-keys -t outer 'tmux attach-session -t inner' Enter
sleep 0.3

# Send Escape to the outer pane. It travels:
#   outer pane stdin → outer tmux → inner tmux terminal input
#   → inner tmux escape-time processing → inner pane (cat)
tmux send-keys -t outer Escape ''

# 200ms window: with escape-time=10 the byte is flushed in ~10ms.
# With the default 500ms it would not have arrived within this window.
sleep 0.2

# Interrupt cat so the file is flushed.
tmux send-keys -t inner C-c
sleep 0.1

if od -An -tx1 /tmp/esc_recv 2>/dev/null | tr -d ' \n' | grep -q '1b'; then
    echo "ESC_DELIVERED_WITHIN_200MS"
else
    echo "ESC_NOT_DELIVERED"
fi
"""

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "bash",
            "-c",
            test_script,
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )

    combined = result.stdout + result.stderr
    assert "ESC_DELIVERED_WITHIN_200MS" in combined, (
        f"Escape key must be delivered through nested tmux within 200ms.\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
