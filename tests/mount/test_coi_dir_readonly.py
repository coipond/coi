"""
The workspace .coi/ directory must be read-only inside the container.

Coi reads <workspace>/.coi/config.toml on every launch (host-side). If an
in-container agent could write that directory it could plant a malicious
config.toml/profile that, on the next launch, mounts arbitrary host paths or
weakens network isolation — a cross-session sandbox escape. Coi mounts .coi/
read-only (protected_paths) so the agent cannot tamper with it.
"""

from pathlib import Path

from support.helpers import run_coi_in_workspace as _run


def test_coi_dir_is_readonly_inside_container(coi_binary, cleanup_containers, workspace_dir):
    """Appending to or creating files under .coi/ from inside must fail."""
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    original = "# project config\n"
    (config_dir / "config.toml").write_text(original)

    # Guard against false-pass: the file must be visible inside the container.
    read_result = _run(coi_binary, workspace_dir, ["cat", "/workspace/.coi/config.toml"])
    assert read_result.returncode == 0, (
        f"workspace .coi/config.toml should be readable inside the container.\n"
        f"stdout: {read_result.stdout}\nstderr: {read_result.stderr}"
    )

    # Modifying the existing config must fail (read-only mount).
    modify = _run(
        coi_binary,
        workspace_dir,
        ["sh", "-c", "echo 'evil = true' >> /workspace/.coi/config.toml"],
    )
    combined = (modify.stdout + modify.stderr).lower()
    assert modify.returncode != 0 or "read-only" in combined, (
        f"Modifying /workspace/.coi/config.toml should fail.\n"
        f"returncode: {modify.returncode}\nstdout: {modify.stdout}\nstderr: {modify.stderr}"
    )

    # Creating a NEW file under .coi/ must also fail (the whole dir is read-only).
    plant = _run(
        coi_binary,
        workspace_dir,
        ["sh", "-c", "echo 'x' > /workspace/.coi/planted.toml"],
    )
    combined2 = (plant.stdout + plant.stderr).lower()
    assert plant.returncode != 0 or "read-only" in combined2, (
        f"Creating /workspace/.coi/planted.toml should fail.\n"
        f"returncode: {plant.returncode}\nstdout: {plant.stdout}\nstderr: {plant.stderr}"
    )

    # The host-side files must be untouched.
    assert (config_dir / "config.toml").read_text() == original
    assert not (config_dir / "planted.toml").exists()
