"""
End-to-end tests for command-sourced env vars (`[defaults.env_commands]`).

Coi runs a host command at session start and injects its trimmed stdout as an
env var inside the container — for minting short-lived secrets without parking
them in the host env or static config. Running a host command is host code
execution, so env_commands is honored ONLY from trusted-scope config
(~/.coi/config.toml / $COI_CONFIG) and stripped from an untrusted project
./.coi/config.toml. A failing command aborts the launch.
"""

import os
import pathlib
import subprocess

SENTINEL = "MINTED_TOKEN_4471"
VAR = "MINTED_SECRET"


def probe_env(coi_binary, workspace_dir, env, var=VAR):
    """Run `coi run` and print the (maybe-injected) env var from the container."""
    return subprocess.run(
        [coi_binary, "run", "--", "sh", "-c", f'echo "VAL=${var}"'],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
        env=env,
    )


def env_gate_active():
    return {k: v for k, v in os.environ.items() if k != "COI_TRUST_ALL"}


def test_env_command_injected_from_trusted_config(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """A trusted-scope ($COI_CONFIG) env_command mints a value that lands in the
    container env, trimmed."""
    cfg = tmp_path / "trusted-config.toml"
    cfg.write_text(f"[defaults.env_commands]\n{VAR} = \"printf '  {SENTINEL}\\n'\"\n")
    env = dict(os.environ)
    env["COI_CONFIG"] = str(cfg)

    r = probe_env(coi_binary, workspace_dir, env)
    assert f"VAL={SENTINEL}" in r.stdout, (
        f"minted env_command value should be injected (and trimmed). out={r.stdout} err={r.stderr}"
    )


def test_env_command_failure_aborts_launch(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """A failing env_command aborts the launch rather than starting a session
    without the credential."""
    cfg = tmp_path / "trusted-config.toml"
    cfg.write_text(f'[defaults.env_commands]\n{VAR} = "echo boom >&2; exit 3"\n')
    env = dict(os.environ)
    env["COI_CONFIG"] = str(cfg)

    r = probe_env(coi_binary, workspace_dir, env)
    assert r.returncode != 0, (
        f"a failing env_command must abort the launch. out={r.stdout} err={r.stderr}"
    )
    assert f"VAL={SENTINEL}" not in r.stdout
    assert VAR in r.stderr, f"error should name the failing variable. err={r.stderr}"


def test_env_command_ignored_from_untrusted_project_config(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """An env_command in the untrusted project ./.coi/config.toml is stripped with
    a warning — host code execution is never honored from project config."""
    cfg_dir = pathlib.Path(workspace_dir) / ".coi"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.toml").write_text(f'[defaults.env_commands]\n{VAR} = "echo {SENTINEL}"\n')
    env = env_gate_active()

    r = probe_env(coi_binary, workspace_dir, env)
    assert f"VAL={SENTINEL}" not in r.stdout, (
        f"untrusted env_command must not be honored. out={r.stdout} err={r.stderr}"
    )
    assert "ignoring 'env_commands'" in r.stderr.lower(), (
        f"expected the strip warning on stderr. err={r.stderr}"
    )
