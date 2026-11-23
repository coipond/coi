"""
Test that the real omp, launched by coi shell, writes its session into the
workspace.

Tests that:
1. omp (installed in the container with its official installer when the image
   lacks it) runs one headless turn against a fake OpenAI server, using the
   models.yml coi copied from the host ~/.omp/agent
2. The session .jsonl lands in <workspace>/.omp-sessions on the host, not in
   ~/.omp/agent/sessions in the container

A wrapper `[tool] binary` (trusted scope) starts the fake server, runs
`omp -p` and writes the exit code to a marker file in the workspace, then
stays alive like an agent would. COI_USE_DUMMY is not set: it would replace
the launched binary.
"""

import shutil
from pathlib import Path

from support.helpers import (
    launch_recorded_tool,
    make_workspace_writable,
    write_trusted_coi_config,
)

MARKER = ".omp-real-marker"
LOG = ".omp-real.log"

FAKE_SERVER = Path(__file__).resolve().parent.parent.parent / "support" / "fake_openai.py"

MODELS_YML = """providers:
  fake:
    baseUrl: http://127.0.0.1:18080/v1
    apiKey: x
    api: openai-completions
    models:
      - id: fake
        name: fake
"""

# The server log stays out of /tmp (systemd-tmpfiles empties it).
WRAPPER = f"""#!/bin/sh
log=/workspace/{LOG}
omp="$(command -v omp || echo "$HOME/.local/bin/omp")"
if [ ! -x "$omp" ]; then
    curl -fsSL https://omp.sh/install | sh >> "$log" 2>&1
    omp="$HOME/.local/bin/omp"
fi
python3 /workspace/.fake-openai.py 18080 > ~/fake-openai.log 2>&1 < /dev/null &
i=0
until curl -sf http://127.0.0.1:18080/v1/models > /dev/null || [ "$i" -ge 150 ]; do
    i=$((i + 1))
    sleep 0.2
done
timeout 120 "$omp" -p --model fake/fake "say hi" < /dev/null >> "$log" 2>&1
printf 'exit=%s\\n' "$?" > /workspace/{MARKER}.tmp
mv /workspace/{MARKER}.tmp /workspace/{MARKER}
exec sleep 300
"""


def test_omp_writes_session_to_workspace(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    The real omp writes its session to <workspace>/.omp-sessions.

    Flow:
    1. Fake HOME with ~/.omp/agent/models.yml naming a fake provider
    2. [tool] name = "omp", binary = the wrapper (trusted scope)
    3. coi shell --background; wait for the wrapper's marker (exit=<code>)
    4. Check omp exited 0 and a session .jsonl is in the host workspace
    """
    fake_home = tmp_path / "fake_home"
    agent_dir = fake_home / ".omp" / "agent"
    agent_dir.mkdir(parents=True)
    (agent_dir / "models.yml").write_text(MODELS_YML)

    workspace = Path(workspace_dir)
    shutil.copy(FAKE_SERVER, workspace / ".fake-openai.py")
    wrapper = workspace / "omp-wrapper.sh"
    wrapper.write_text(WRAPPER)
    wrapper.chmod(0o755)
    make_workspace_writable(workspace_dir)

    env = write_trusted_coi_config('[tool]\nname = "omp"\nbinary = "/workspace/omp-wrapper.sh"\n')
    env.pop("COI_USE_DUMMY", None)
    env["HOME"] = str(fake_home)

    log_path = workspace / LOG
    try:
        recorded = launch_recorded_tool(
            coi_binary, workspace_dir, env, workspace / MARKER, marker_timeout=420
        )
    except AssertionError as e:
        log = log_path.read_text() if log_path.exists() else "(no log)"
        raise AssertionError(f"{e}\nomp log:\n{log}") from e
    log = log_path.read_text() if log_path.exists() else "(no log)"
    assert recorded.get("exit") == "0", f"omp -p failed ({recorded}). log:\n{log}"

    sessions = list((workspace / ".omp-sessions").glob("**/*.jsonl"))
    assert sessions, (
        f"omp did not write its session into <workspace>/.omp-sessions "
        f"(PI_CODING_AGENT_SESSION_DIR). log:\n{log}"
    )
