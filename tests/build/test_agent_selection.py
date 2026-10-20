"""
Tests for selectable agents in the base image build (issue #454).

profiles/default/build.sh used to call install_claude_cli / install_opencode /
install_pi unconditionally. It now dispatches through install_selected_agents,
which installs the agents named in $COI_AGENTS (comma/space separated) and falls
back to the DEFAULT agent set when COI_AGENTS is unset (claude/opencode2/pi —
opt-in agents like codex (#698) and OpenCode v1 (opencode) are excluded and must
be requested explicitly).

These tests source the REAL install_selected_agents from build.sh (like
test_opencode_arch_selection.py sources opencode_asset_arch), stub the per-agent
install functions as markers, and assert the dispatch. Hermetic: no network, no Incus.
"""

import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

BUILD_SH = Path(__file__).resolve().parents[2] / "profiles" / "default" / "build.sh"

# Stub the per-agent installers + log as markers, then source ONLY the real
# install_selected_agents function and run it. The stubs are defined before the
# source, so the dispatch resolves to them at call time.
_RUN = r"""
set -e
install_claude_cli() { echo "AGENT:claude"; }
install_opencode()   { echo "AGENT:opencode"; }
install_pi()         { echo "AGENT:pi"; }
install_codex()      { echo "AGENT:codex"; }
install_opencode2()  { echo "AGENT:opencode2"; }
log()                { echo "LOG:$*"; }
source <(sed -n '/^install_selected_agents()/,/^}/p' "$BUILD_SH")
install_selected_agents
"""


def _run(coi_agents=None):
    env = {**os.environ, "BUILD_SH": str(BUILD_SH)}
    if coi_agents is not None:
        env["COI_AGENTS"] = coi_agents
    else:
        env.pop("COI_AGENTS", None)
    r = subprocess.run(["bash", "-c", _RUN], capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, f"dispatch failed: {r.stdout}{r.stderr}"
    return [
        line.removeprefix("AGENT:") for line in r.stdout.splitlines() if line.startswith("AGENT:")
    ], r.stdout


def test_unset_installs_default_agents():
    """COI_AGENTS unset installs the default agent set (codex, per #698, and
    OpenCode v1 are opt-in and deliberately excluded)."""
    agents, _ = _run(coi_agents=None)
    assert agents == ["claude", "opencode2", "pi"], agents


def test_empty_installs_default_agents():
    """An empty COI_AGENTS also falls back to the default agent set."""
    agents, _ = _run(coi_agents="")
    assert agents == ["claude", "opencode2", "pi"], agents


def test_codex_opt_in():
    """codex installs only when explicitly requested (#698)."""
    agents, _ = _run(coi_agents="claude,codex")
    assert agents == ["claude", "codex"], agents


def test_opencode_v1_opt_in():
    """OpenCode v1 (opencode) installs only when explicitly requested, alone or
    next to v2."""
    agents, _ = _run(coi_agents="opencode")
    assert agents == ["opencode"], agents
    agents, _ = _run(coi_agents="opencode,opencode2")
    assert agents == ["opencode", "opencode2"], agents


def test_single_agent_selection():
    """Only the named agent is installed."""
    agents, _ = _run(coi_agents="claude")
    assert agents == ["claude"], agents


def test_subset_comma_separated():
    """A comma-separated subset installs exactly those, in order."""
    agents, _ = _run(coi_agents="claude,pi")
    assert agents == ["claude", "pi"], agents


def test_subset_space_separated():
    """Space separation works too."""
    agents, _ = _run(coi_agents="opencode pi")
    assert agents == ["opencode", "pi"], agents


def test_unknown_agent_warns_and_skips():
    """An unknown name is warned about and skipped, not fatal (coi validates
    host-side before build; this is defense-in-depth)."""
    agents, out = _run(coi_agents="claude bogus")
    assert agents == ["claude"], agents
    assert "WARNING" in out and "bogus" in out, out


# --- end-to-end via the real coi binary (config -> validation) ---------------


def _skip_without_incus(coi_binary):
    if (
        subprocess.run(
            [coi_binary, "image", "exists", "coi-default"], capture_output=True
        ).returncode
        != 0
    ):
        pytest.skip("coi base image not available")


def test_coi_build_rejects_unknown_agent(coi_binary, workspace_dir):
    """`coi build` fails fast with a clear error when [container.build] agents names an
    unsupported agent — validation happens before any image build, so this is cheap and
    proves the config -> default-profile -> validate wiring end to end (#454)."""
    _skip_without_incus(coi_binary)
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(exist_ok=True)
    (coi_dir / "config.toml").write_text(
        '[container]\nimage = "coi-default"\n\n[container.build]\nagents = ["bogus"]\n'
    )
    result = subprocess.run(
        [coi_binary, "build"], capture_output=True, text=True, timeout=120, cwd=workspace_dir
    )
    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0, (
        f"unknown agent must fail the build:\n{result.stdout}{result.stderr}"
    )
    assert "unknown agent" in combined and "bogus" in combined, combined


def test_coi_build_warns_when_configured_tool_not_built(coi_binary, workspace_dir):
    """`coi build` warns when the agents list omits the tool the config runs, before
    building. Gated on an existing coi-default (no --force) so it warns then skips —
    no expensive rebuild."""
    _skip_without_incus(coi_binary)
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(exist_ok=True)
    (coi_dir / "config.toml").write_text(
        '[tool]\nname = "claude"\n\n[container]\nimage = "coi-default"\n\n'
        '[container.build]\nagents = ["opencode"]\n'
    )
    result = subprocess.run(
        [coi_binary, "build"], capture_output=True, text=True, timeout=120, cwd=workspace_dir
    )
    combined = result.stdout + result.stderr
    # Warn fired (tool 'claude' not in agents) and the build did not error out.
    assert "claude" in combined.lower() and "warning" in combined.lower(), combined
    assert result.returncode == 0, f"warn is non-fatal; build should skip/succeed:\n{combined}"


def _probe(coi_binary, workspace_dir, script):
    """Run `bash -lc script` in a throwaway container of coi-default."""
    probe = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "bash", "-lc", script],
        capture_output=True,
        text=True,
        timeout=300,
    )
    out = probe.stdout + probe.stderr
    assert probe.returncode == 0, f"probe run failed:\n{out}"
    return out


@contextmanager
def _rebuilt_coi_default(coi_binary, workspace_dir, agents):
    """Rebuild coi-default with `[container.build] agents = agents` (None: no
    agents key, so the default set), then restore the original image for
    sibling tests in this lane. Skips where coi-default or incus is missing."""
    _skip_without_incus(coi_binary)
    if shutil.which("incus") is None:
        pytest.skip("incus CLI not available")

    # Capture the original image fingerprint so it can be restored afterwards. `coi
    # build --force` re-points the coi-default alias at the freshly built (slim) image
    # and leaves the original in the store, so restoring is just deleting the slim image
    # and re-aliasing this fingerprint — no multi-hundred-MB export needed.
    info = subprocess.run(
        ["incus", "image", "info", "coi-default"], capture_output=True, text=True, timeout=60
    )
    m = re.search(r"Fingerprint:\s*([0-9a-f]+)", info.stdout)
    if info.returncode != 0 or not m:
        pytest.skip("could not read coi-default fingerprint to back it up")
    orig_fp = m.group(1)

    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(exist_ok=True)
    config = '[container]\nimage = "coi-default"\n'
    if agents is not None:
        agents_toml = ", ".join(f'"{a}"' for a in agents)
        config += f"\n[container.build]\nagents = [{agents_toml}]\n"
    (coi_dir / "config.toml").write_text(config)

    try:
        build = subprocess.run(
            [coi_binary, "build", "--force"],
            capture_output=True,
            text=True,
            timeout=1500,
            cwd=workspace_dir,
        )
        assert build.returncode == 0, (
            f"build with agents={agents} failed:\n{build.stdout}{build.stderr}"
        )
        yield
    finally:
        # Restore the shared coi-default for sibling tests in this lane (which run in
        # randomized order, so a slip here cascades). `coi build --force` re-pointed
        # coi-default at the slim image and left the original in the store. Delete the
        # slim image — which drops its coi-default alias AND reclaims disk in one step —
        # then re-alias the original fingerprint. Deleting the image first means the
        # subsequent alias create cannot fail with "already exists", and the alias is
        # re-created immediately, so coi-default is never left unaliased on this path.
        cur = subprocess.run(
            ["incus", "image", "info", "coi-default"], capture_output=True, text=True, timeout=60
        )
        mcur = re.search(r"Fingerprint:\s*([0-9a-f]+)", cur.stdout)
        slim_fp = mcur.group(1) if mcur else None

        orig_present = (
            subprocess.run(
                ["incus", "image", "info", orig_fp], capture_output=True, text=True, timeout=60
            ).returncode
            == 0
        )

        # Only act when the build actually produced a distinct slim image and the
        # original survives. Otherwise (build skipped/failed -> still original, or the
        # original is somehow gone) coi-default already resolves to a working image, so
        # leave it as-is rather than risk unaliasing the shared image.
        if orig_present and slim_fp and slim_fp != orig_fp:
            subprocess.run(
                ["incus", "image", "delete", slim_fp], capture_output=True, text=True, timeout=120
            )
            restore = subprocess.run(
                ["incus", "image", "alias", "create", "coi-default", orig_fp],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if restore.returncode != 0:
                # The slim delete didn't drop the alias (e.g. image was locked); force
                # it off and recreate so coi-default ends up on the original image.
                subprocess.run(
                    ["incus", "image", "alias", "delete", "coi-default"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                restore = subprocess.run(
                    ["incus", "image", "alias", "create", "coi-default", orig_fp],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            assert restore.returncode == 0, (
                f"failed to re-alias coi-default to the original image: "
                f"{restore.stdout}{restore.stderr}"
            )


def test_slim_build_installs_only_selected_agents(coi_binary, workspace_dir):
    """End-to-end proof (#454, review finding 4): a real `coi build` with
    agents=["claude"] produces a coi-default image that HAS claude but NOT the other agents.

    This is the one link the unit + hermetic tests cannot cover on their own — it
    exercises the whole chain for real: project config -> BuildOptions.Agents ->
    agentEnv -> COI_AGENTS env -> ExecCommand -> build.sh's install_selected_agents ->
    the actual installed binary set. The shared coi-default image is backed up and
    restored so sibling tests in this lane are unaffected. Slow (a real image build);
    only runs where coi-default + incus already exist (the core-build CI lane)."""
    with _rebuilt_coi_default(coi_binary, workspace_dir, ["claude"]):
        # claude present, the two unselected agents absent. `command -v` failing is
        # exactly the runtime footgun the selector must avoid for the configured tool.
        out = _probe(
            coi_binary,
            workspace_dir,
            "for a in claude opencode opencode2 pi; do "
            'command -v "$a" >/dev/null 2>&1 && echo HAVE:$a || echo MISS:$a; done',
        )
        lines = out.splitlines()
        assert "HAVE:claude" in lines, f"claude must be installed with agents=[claude]:\n{out}"
        assert "MISS:opencode" in lines, f"opencode must be ABSENT with agents=[claude]:\n{out}"
        assert "MISS:pi" in lines, f"pi must be ABSENT with agents=[claude]:\n{out}"
        assert "MISS:opencode2" in lines, f"opencode2 must be ABSENT with agents=[claude]:\n{out}"


def test_default_build_installs_opencode2_not_v1(coi_binary, workspace_dir):
    """A real `coi build` with no agents list installs OpenCode v2 as opencode2,
    in its own directory, and no OpenCode v1 (opt-in). Same image backup/restore
    as the slim build test; runs only where coi-default + incus exist
    (core-build)."""
    with _rebuilt_coi_default(coi_binary, workspace_dir, None):
        out = _probe(
            coi_binary,
            workspace_dir,
            'echo "V2:$(opencode2 --version)"; readlink -f /usr/local/bin/opencode2; '
            "command -v opencode >/dev/null 2>&1 && echo HAVE:opencode || echo MISS:opencode",
        )
        assert re.search(r"^V2:opencode v2\.\d+\.\d+$", out, re.MULTILINE), (
            f"opencode2 must be OpenCode v2:\n{out}"
        )
        assert "/.opencode2/bin/opencode" in out, f"opencode2 must have its own directory:\n{out}"
        assert "MISS:opencode" in out.splitlines(), (
            f"OpenCode v1 must not be installed by default:\n{out}"
        )
