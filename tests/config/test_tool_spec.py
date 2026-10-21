"""
Non-executing launch spec: `coi tool spec` (#751).

`coi tool spec` prints — without executing — the exact command + tool-derived
env for launching the profile's tool inside an existing container. An external
orchestrator then runs that command through its own container exec + tmux. coi
builds the command from the profile's tool (session id, resume, model,
permission) and stages the prompt into the container; the orchestrator owns
execution, so no coi-owned tmux/exit-file machinery is involved.

These assert the end-to-end contract with the dummy tool against a real
container:

1. `coi tool spec --json` prints {command, env} where command is the tool's argv
   (dummy-overridden binary) with the prompt embedded via "$(cat …)".
2. The prompt is staged into the container at ~/.coi/runs/<id>.prompt verbatim.
3. The profile's [tool.claude] model is emitted in env (model/effort only), and
   secrets are absent.
"""

import json
import os
import subprocess
import time

import pytest
from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    spawn_coi,
    wait_for_container_ready,
)


def _write_config(workspace_dir, tool="claude", model=None, preserve_workspace=False):
    config_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(config_dir, exist_ok=True)
    body = f'[container]\npersistent = true\n\n[tool]\nname = "{tool}"\n'
    if model:
        body += f'\n[tool.{tool}]\nmodel = "{model}"\n'
    if preserve_workspace:
        body += "\n[paths]\npreserve_workspace_path = true\n"
    with open(os.path.join(config_dir, "config.toml"), "w") as f:
        f.write(body)


def _container_workspace_path(container):
    """The path the workspace disk is actually mounted at inside the container."""
    r = subprocess.run(
        ["incus", "config", "device", "get", container, "workspace", "path"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    return r.stdout.strip() or "/workspace"


def _boot_container(coi_binary, workspace_dir):
    """Boot a real container via `coi shell` (dummy tool) and return (child,
    container_name) once it's ready for `coi tool spec` to target."""
    container_name = calculate_container_name(workspace_dir, 1)
    child = spawn_coi(
        coi_binary,
        ["shell"],
        cwd=workspace_dir,
        env={"COI_USE_DUMMY": "1"},
        timeout=120,
    )
    wait_for_container_ready(child, timeout=90)
    time.sleep(3)
    return child, container_name


def _teardown(coi_binary, child, container_name):
    try:
        child.send("\x03")
        time.sleep(0.5)
        child.send("sudo poweroff")
        time.sleep(0.3)
        child.send("\x0d")
        try:
            child.expect(EOF, timeout=60)
        except TIMEOUT:
            pass
    finally:
        try:
            child.close(force=True)
        except Exception:
            pass
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )


def _cat_in_container(container, path):
    r = subprocess.run(
        ["incus", "exec", container, "--", "cat", path],
        capture_output=True,
        text=True,
        timeout=20,
    )
    return r.stdout + r.stderr


def _spec(
    coi_binary,
    container,
    workspace_dir,
    session_id,
    prompt_file=None,
    system_prompt_file=None,
    extra=None,
):
    argv = [
        coi_binary,
        "tool",
        "spec",
        "--container",
        container,
        "--session-id",
        session_id,
        "--json",
    ]
    if prompt_file is not None:
        argv += ["--prompt-file", str(prompt_file)]
    if system_prompt_file is not None:
        argv += ["--system-prompt-file", str(system_prompt_file)]
    if extra:
        argv += extra
    r = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "COI_USE_DUMMY": "1"},
        cwd=workspace_dir,
    )
    assert r.returncode == 0, f"tool spec failed. stdout:{r.stdout}\nstderr:{r.stderr}"
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_tool_spec_command_and_prompt_staging(coi_binary, workspace_dir, cleanup_containers):
    """Core: spec prints {command, env}; the prompt is staged verbatim and
    referenced by argv via "$(cat …)"; env carries the profile model only."""
    _write_config(workspace_dir, model="coi-test-spec-opus")
    prompt_file = os.path.join(workspace_dir, "prompt.txt")
    prompt_text = "hello 'single' \"double\" $(whoami) && echo pwned\nline2\n"
    with open(prompt_file, "w") as f:
        f.write(prompt_text)

    child, container = _boot_container(coi_binary, workspace_dir)
    try:
        sid = "spec-session-1"
        spec = _spec(coi_binary, container, workspace_dir, sid, prompt_file)

        assert isinstance(spec.get("command"), list) and spec["command"], spec
        # Dummy override replaces the binary; the prompt is the trailing cat-subst.
        assert spec["command"][0] == "dummy", spec["command"]
        staged_ref = f'"$(cat /home/code/.coi/runs/{sid}.prompt)"'
        assert spec["command"][-1] == staged_ref, spec["command"]

        # Claude embeds the prompt in argv, so no out-of-band prompt field.
        assert "prompt" not in spec, spec

        # Env is tool-derived only (model), no secrets.
        assert spec["env"].get("ANTHROPIC_MODEL") == "coi-test-spec-opus", spec["env"]
        assert not any("TOKEN" in k or "KEY" in k for k in spec["env"]), spec["env"]

        # Prompt staged verbatim — no command substitution ran.
        staged = _cat_in_container(container, f"/home/code/.coi/runs/{sid}.prompt")
        assert "$(whoami)" in staged and "pwned" in staged and "line2" in staged, staged
    finally:
        _teardown(coi_binary, child, container)


def test_tool_spec_system_prompt_staging(coi_binary, workspace_dir, cleanup_containers):
    """--system-prompt-file stages a .sys file and Claude references it via
    --append-system-prompt "$(cat …)" in the printed command."""
    _write_config(workspace_dir)
    prompt_file = os.path.join(workspace_dir, "p.txt")
    with open(prompt_file, "w") as f:
        f.write("do the thing")
    sys_file = os.path.join(workspace_dir, "sys.txt")
    with open(sys_file, "w") as f:
        f.write("you are a terse assistant")

    child, container = _boot_container(coi_binary, workspace_dir)
    try:
        sid = "spec-sys-1"
        spec = _spec(
            coi_binary, container, workspace_dir, sid, prompt_file, system_prompt_file=sys_file
        )
        joined = " ".join(spec["command"])
        assert "--append-system-prompt" in joined, spec["command"]
        assert f'"$(cat /home/code/.coi/runs/{sid}.sys)"' in joined, spec["command"]
        assert "terse assistant" in _cat_in_container(container, f"/home/code/.coi/runs/{sid}.sys")
    finally:
        _teardown(coi_binary, child, container)


def test_tool_spec_without_prompt(coi_binary, workspace_dir, cleanup_containers):
    """With no --prompt-file, the command is the bare tool launch (the
    orchestrator sends the first prompt itself), and no prompt file is staged."""
    _write_config(workspace_dir)
    child, container = _boot_container(coi_binary, workspace_dir)
    try:
        sid = "spec-noprompt-1"
        spec = _spec(coi_binary, container, workspace_dir, sid)
        assert spec["command"][0] == "dummy", spec["command"]
        # No cat-subst trailing arg since there is no prompt.
        assert not any("$(cat" in a for a in spec["command"]), spec["command"]
        # No prompt file was staged.
        absent = _cat_in_container(container, f"/home/code/.coi/runs/{sid}.prompt")
        assert "No such file" in absent or absent.strip() == "", absent
    finally:
        _teardown(coi_binary, child, container)


def test_tool_spec_codex_tool_agnostic(coi_binary, workspace_dir, cleanup_containers):
    """A different tool (codex) produces a spec through the same API with no
    caller changes — coi owns the per-tool command shape. Codex embeds the
    prompt as a trailing positional."""
    _write_config(workspace_dir, tool="codex")
    prompt_file = os.path.join(workspace_dir, "p.txt")
    with open(prompt_file, "w") as f:
        f.write("codex please")

    child, container = _boot_container(coi_binary, workspace_dir)
    try:
        sid = "spec-codex-1"
        spec = _spec(coi_binary, container, workspace_dir, sid, prompt_file)
        assert spec["command"][0] == "dummy", spec["command"]
        assert spec["command"][-1] == f'"$(cat /home/code/.coi/runs/{sid}.prompt)"', spec["command"]
        assert "codex please" in _cat_in_container(container, f"/home/code/.coi/runs/{sid}.prompt")
    finally:
        _teardown(coi_binary, child, container)


def test_tool_spec_opencode_out_of_band_prompt(coi_binary, workspace_dir, cleanup_containers):
    """A tool that can't embed the prompt in argv (opencode) gets a `prompt`
    field with the staged in-container path, and the command has no "$(cat …)"
    prompt arg — the orchestrator delivers it out-of-band after launch."""
    _write_config(workspace_dir, tool="opencode")
    prompt_file = os.path.join(workspace_dir, "p.txt")
    with open(prompt_file, "w") as f:
        f.write("opencode please")

    child, container = _boot_container(coi_binary, workspace_dir)
    try:
        sid = "spec-opencode-1"
        spec = _spec(coi_binary, container, workspace_dir, sid, prompt_file)
        assert spec["command"][0] == "dummy", spec["command"]
        # Prompt is NOT embedded in argv for a non-embedding tool.
        assert not any("$(cat" in a for a in spec["command"]), spec["command"]
        # It's surfaced as the staged in-container prompt path instead.
        assert spec.get("prompt") == f"/home/code/.coi/runs/{sid}.prompt", spec
        assert "opencode please" in _cat_in_container(
            container, f"/home/code/.coi/runs/{sid}.prompt"
        )
    finally:
        _teardown(coi_binary, child, container)


def test_tool_spec_env_uses_container_workspace_path(coi_binary, workspace_dir, cleanup_containers):
    """A tool whose GetContainerEnv derives paths from the workspace (pi's
    session dir) must be computed against the container's ACTUAL workspace mount,
    not a hardcoded /workspace. With preserve_workspace_path the workspace mounts
    at the host path (under /tmp, not a system dir), so the env must reflect that."""
    _write_config(workspace_dir, tool="pi", preserve_workspace=True)
    child, container = _boot_container(coi_binary, workspace_dir)
    try:
        ws = _container_workspace_path(container)
        # Sanity: preserve_workspace_path really did move the mount off the default.
        assert ws != "/workspace", f"expected a preserved non-default mount, got {ws!r}"

        spec = _spec(coi_binary, container, workspace_dir, "spec-ws-1")
        assert spec["env"].get("PI_CODING_AGENT_SESSION_DIR") == f"{ws}/.pi-sessions", spec["env"]
    finally:
        _teardown(coi_binary, child, container)


def test_tool_spec_resume_id_asserts_without_discovery(
    coi_binary, workspace_dir, cleanup_containers
):
    """--resume-id builds a resume command for the given id verbatim, without
    consulting coi's host-side session store (#753). The test workspace has no
    ~/.coi session for the id, so a discovery path (--continue) would fall back
    to fresh; --resume-id must still render a resume command."""
    _write_config(workspace_dir)
    child, container = _boot_container(coi_binary, workspace_dir)
    try:
        spec = _spec(
            coi_binary,
            container,
            workspace_dir,
            "new-run-1",
            extra=["--resume-id", "prior-run-xyz"],
        )
        cmd = spec["command"]
        # claude renders `--resume <id>`, and a resume replaces --session-id.
        assert "--resume" in cmd, cmd
        assert "prior-run-xyz" in cmd, cmd
        assert "--session-id" not in cmd, cmd
        # No secrets leaked into env regardless of the resume strategy.
        assert not any("TOKEN" in k or "KEY" in k for k in spec["env"]), spec["env"]
    finally:
        _teardown(coi_binary, child, container)


def test_tool_spec_resume_latest_renders_continue(coi_binary, workspace_dir, cleanup_containers):
    """--resume-latest (no id) renders a resume-latest command with no id and no
    --session-id (#753). For claude the launch path emits a trailing
    `--continue` (not bare `--resume`, which would open Claude's interactive
    picker and hang a headless launch — #754)."""
    _write_config(workspace_dir)
    child, container = _boot_container(coi_binary, workspace_dir)
    try:
        spec = _spec(coi_binary, container, workspace_dir, "new-run-1", extra=["--resume-latest"])
        cmd = spec["command"]
        # Resume-latest for claude is a trailing `--continue`: no id after it, no
        # --session-id (not a fresh launch), no bare --resume, and no prompt.
        assert cmd[-1] == "--continue", cmd
        assert "--resume" not in cmd, cmd
        assert "--session-id" not in cmd, cmd
        assert not any("$(cat" in a for a in cmd), cmd
    finally:
        _teardown(coi_binary, child, container)


def test_tool_spec_resume_modes_mutually_exclusive(coi_binary, workspace_dir):
    """--continue / --resume-id / --resume-latest express conflicting resume
    strategies; setting more than one is a usage error (fast: checked before
    container access)."""
    _write_config(workspace_dir)
    for extra in (
        ["--resume-id", "abc", "--continue"],
        ["--resume-id", "abc", "--resume-latest"],
        ["--resume-latest", "--continue"],
    ):
        r = _run_spec_raw(coi_binary, workspace_dir, "good-sid", extra=extra)
        out = r.stdout + r.stderr
        assert r.returncode == 2, f"{extra}: expected exit 2, got {r.returncode}: {out}"
        assert "mutually exclusive" in out, f"{extra}: {out}"


def test_tool_spec_rejects_inherited_global_resume(coi_binary, workspace_dir):
    """`coi tool spec` has no bare --resume of its own: that name is the root's
    persistent session-resume flag (a string), inherited here but never read by
    this handler. Left alone it would be silently swallowed (fresh launch, no
    error) — a quiet foot-gun. The command rejects it loudly and points at the
    two real strategies. Both `--resume` (NoOptDefVal) and `--resume=<id>` are
    rejected; checked before container access, so no incus needed."""
    _write_config(workspace_dir)
    for extra in (["--resume"], ["--resume=abc"]):
        r = _run_spec_raw(coi_binary, workspace_dir, "good-sid", extra=extra)
        out = r.stdout + r.stderr
        assert r.returncode == 2, f"{extra}: expected exit 2, got {r.returncode}: {out}"
        assert "has no --resume" in out, f"{extra}: {out}"
        assert "--resume-latest" in out and "--resume-id" in out, f"{extra}: {out}"


def test_tool_spec_rejects_unsafe_resume_id(coi_binary, workspace_dir):
    """--resume-id is shell-interpolated / a filename component, so an unsafe
    value is rejected (same as --session-id / --continue)."""
    _write_config(workspace_dir)
    r = _run_spec_raw(coi_binary, workspace_dir, "good-sid", extra=["--resume-id", "bad id"])
    assert r.returncode == 2, r.stdout + r.stderr
    assert "invalid session id" in (r.stdout + r.stderr)


def test_tool_spec_accepts_safe_resume_id(coi_binary, workspace_dir):
    """A safe --resume-id passes validation (and mutual-exclusion), then fails
    downstream on the bogus container — proving it was accepted, not discovered."""
    _write_config(workspace_dir)
    r = _run_spec_raw(coi_binary, workspace_dir, "good-sid", extra=["--resume-id", "prior-abc"])
    out = r.stdout + r.stderr
    assert "invalid session id" not in out, out
    assert "mutually exclusive" not in out, out
    assert r.returncode != 0


def test_tool_spec_requires_container(coi_binary, workspace_dir):
    """`coi tool spec` without --container is a usage error (fast: the check
    short-circuits before any container access, so no boot needed)."""
    _write_config(workspace_dir)
    r = subprocess.run(
        [coi_binary, "tool", "spec", "--session-id", "x", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
    )
    assert r.returncode != 0, "missing --container must fail"
    assert "container" in (r.stdout + r.stderr)


def test_tool_spec_requires_session_id(coi_binary, workspace_dir):
    """`coi tool spec` without --session-id is a usage error (fast: no boot; the
    check runs before the container is touched)."""
    _write_config(workspace_dir)
    r = subprocess.run(
        [coi_binary, "tool", "spec", "--container", "nonexistent-ctr", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
    )
    assert r.returncode != 0, "missing --session-id must fail"
    assert "session-id" in (r.stdout + r.stderr)


def _run_spec_raw(coi_binary, workspace_dir, session_id, extra=None):
    """Run `coi tool spec` with a raw (possibly unsafe) session id and return the
    completed process. Uses a bogus --container: session-id validation runs
    before any container access, so a rejected id fails without booting."""
    argv = [
        coi_binary,
        "tool",
        "spec",
        "--container",
        "nonexistent-ctr",
        "--session-id",
        session_id,
        "--json",
    ]
    if extra:
        argv += extra
    return subprocess.run(argv, capture_output=True, text=True, timeout=30, cwd=workspace_dir)


@pytest.mark.parametrize(
    "bad_sid,label",
    [
        ("has space", "space"),
        ("x;reboot", "shell-metachar"),
        ("$(whoami)", "command-substitution"),
        ("a`id`", "backtick"),
        ('a"b', "double-quote"),
        ("../../etc/passwd", "path-traversal"),
        ("a/b", "path-separator"),
        ("-leadingdash", "leading-dash"),
        ("x" * 65, "too-long"),
    ],
)
def test_tool_spec_rejects_unsafe_session_id(coi_binary, workspace_dir, bad_sid, label):
    """An unsafe --session-id is rejected up front (exit 2) before the id can
    reach a filesystem path or the shell-joined launch command. The error must
    be about the session id, not a downstream 'container not found'."""
    _write_config(workspace_dir)
    r = _run_spec_raw(coi_binary, workspace_dir, bad_sid)
    assert r.returncode == 2, f"[{label}] expected exit 2, got {r.returncode}: {r.stdout}{r.stderr}"
    out = r.stdout + r.stderr
    assert "invalid session id" in out, f"[{label}] expected validation error, got:\n{out}"
    # It must NOT have proceeded to container access.
    assert "not running" not in out and "not found" not in out, (
        f"[{label}] validation must precede container access:\n{out}"
    )


def test_tool_spec_rejects_unsafe_continue_id(coi_binary, workspace_dir):
    """An explicit --continue=<id> is validated too (it selects a session dir to
    read); an unsafe value is rejected before any filesystem lookup."""
    _write_config(workspace_dir)
    r = _run_spec_raw(coi_binary, workspace_dir, "good-sid", extra=["--continue=../escape"])
    assert r.returncode == 2, f"expected exit 2, got {r.returncode}: {r.stdout}{r.stderr}"
    assert "invalid session id" in (r.stdout + r.stderr)


def test_tool_spec_accepts_safe_session_id(coi_binary, workspace_dir):
    """A safe session id passes validation — it then fails later on the bogus
    container, proving the id itself was accepted (no 'invalid session id')."""
    _write_config(workspace_dir)
    # UUID-shaped and slug-shaped ids are both valid.
    for sid in ("1b4e28ba-2fa1-11d2-883f-0016d3cca427", "workspace-session"):
        r = _run_spec_raw(coi_binary, workspace_dir, sid)
        out = r.stdout + r.stderr
        # The id passed validation (no validation error) but the run still fails
        # because the container doesn't exist — proving it got past the id check.
        assert "invalid session id" not in out, f"{sid!r} should be accepted, got:\n{out}"
        assert r.returncode != 0, f"{sid!r}: expected downstream failure on a bogus container"


def test_tool_spec_help(coi_binary):
    r = subprocess.run(
        [coi_binary, "tool", "spec", "--help"], capture_output=True, text=True, timeout=30
    )
    out = r.stdout + r.stderr
    for needle in (
        "--container",
        "--session-id",
        "--prompt-file",
        "--continue",
        "--resume-id",
        "--resume-latest",
        "--json",
    ):
        assert needle in out, f"expected {needle!r} in `coi tool spec --help`, got:\n{out}"
