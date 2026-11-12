"""
Test for coi run - [[credentials]] file mode, owner and catalog bundles.

Tests that:
1. An ad-hoc credential is owned by the code user (uid/gid 1000) and gets
   its `mode`, whatever the host file's mode.
2. `bundle = "ollama"` copies ~/.ollama/id_ed25519 from the host home into
   the container home (its relative catalog path resolves under
   /home/code), owned by uid/gid 1000 with the bundle's mode 0600.
"""

import subprocess

from support.helpers import write_trusted_coi_config


def _run_stat(coi_binary, workspace_dir, env, path):
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            f"stat -c '%u:%g %a' {path} && cat {path}",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, f"coi run should succeed. stderr: {result.stderr}"
    return result.stdout


def test_run_credential_owner_and_mode(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """An ad-hoc credential is owned by 1000:1000 and chmod'ed to its mode."""
    secret = tmp_path / "coi-test-cred.txt"
    content = "COI_CRED_MODE_OWNER_4b7e"
    secret.write_text(content)
    secret.chmod(0o644)

    env = write_trusted_coi_config(
        f'[[credentials]]\nhost = "{secret}"\n'
        'container = "/home/code/.coi-test-cred"\nmode = "0600"\n'
    )

    out = _run_stat(coi_binary, workspace_dir, env, "/home/code/.coi-test-cred")
    assert "1000:1000 600" in out, f"credential should be 1000:1000 mode 600. Got:\n{out}"
    assert content in out, f"credential content should be copied. Got:\n{out}"


def test_run_credential_bundle_ollama(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """bundle = "ollama" seeds ~/.ollama/id_ed25519 under the container home."""
    fake_home = tmp_path / "fake_home"
    ollama_dir = fake_home / ".ollama"
    ollama_dir.mkdir(parents=True)
    key = ollama_dir / "id_ed25519"
    content = "COI_OLLAMA_BUNDLE_KEY_8d21"
    key.write_text(content)
    key.chmod(0o644)

    env = write_trusted_coi_config('[[credentials]]\nbundle = "ollama"\n')
    env["HOME"] = str(fake_home)

    out = _run_stat(coi_binary, workspace_dir, env, "/home/code/.ollama/id_ed25519")
    assert "1000:1000 600" in out, f"bundle file should be 1000:1000 mode 600. Got:\n{out}"
    assert content in out, f"bundle file content should be copied. Got:\n{out}"
