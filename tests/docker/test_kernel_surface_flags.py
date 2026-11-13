"""
Tests for the kernel attack-surface hardening flags:
[container] docker and [security] reduce_kernel_surface.

These assert the instance config `coi container launch` applies — the same
robust path test_docker_flags_enabled.py uses — rather than a full `coi run`
launch, so they don't depend on the nested-idmap container START that CI's
container lane cannot always complete. What the flags CONTROL is the incus
config; a real boot+smoke under the deny list is covered by Go-level tests and
manual verification.

Covered:
1. [container] docker = false (a tightening, honored from project scope)
   launches with none of the four Docker-support keys.
2. [security] reduce_kernel_surface = true (trusted scope) disables Docker
   support AND sets security.syscalls.deny to the full deny list.
3. An untrusted project config's docker = true cannot re-enable nesting that
   trusted config disabled.
4. [security] reduce_kernel_surface_strict = true (trusted scope) implies the
   base tier AND adds perf_event_open to security.syscalls.deny.
5. A container with reduce_kernel_surface actually BOOTS (reaches RUNNING) —
   catches malformed / init-killing deny policies a config assertion misses.
6. The STRICT tier container also BOOTS.
7. The deny value's FORMAT: \n-separated, one entry per line, each with an
   explicit "errno 1" action (guards the space-separated / bare-name bugs at
   config level, so it runs even where the container can't start).
"""

import os
import subprocess

import pytest

from support.helpers import container_config_get

DENY_SYSCALLS = [
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "bpf",
    "userfaultfd",
    "keyctl",
    "add_key",
    "request_key",
]

DOCKER_KEYS = [
    "security.nesting",
    "security.syscalls.intercept.mknod",
    "security.syscalls.intercept.setxattr",
    "linux.sysctl.net.ipv4.ip_unprivileged_port_start",
]


def incus_state(container_name):
    result = subprocess.run(
        ["incus", "--project", "default", "list", container_name, "-c", "s", "-f", "csv"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def skip_unless_bootable(coi_binary):
    """Launch coi-default bare; skip the calling test if this environment can't
    boot it at all (CI's nested lane sometimes can't complete a container START
    regardless of hardening). Cleans up the baseline container."""
    base = "coi-ks-boot-base"
    try:
        launch(coi_binary, base)
        if incus_state(base) != "RUNNING":
            pytest.skip("environment cannot boot coi-default bare; skipping boot assertion")
    finally:
        subprocess.run(["incus", "--project", "default", "delete", base, "--force"], timeout=60)


def launch(coi_binary, name, env=None, cwd=None):
    """coi container launch applies the kernel-surface policy at init, before
    the container start that CI's nested environment may not complete — so the
    config assertions hold regardless of whether the start itself succeeds."""
    return subprocess.run(
        [coi_binary, "container", "launch", "coi-default", name],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=cwd,
    )


def write_project_config(workspace_dir, content):
    coi_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(coi_dir, exist_ok=True)
    with open(os.path.join(coi_dir, "config.toml"), "w") as f:
        f.write(content)


def test_docker_disabled_via_project_config(coi_binary, cleanup_containers, workspace_dir):
    """[container] docker = false is a tightening, so a project config may set
    it; the container then carries none of the Docker-support keys and no
    syscall deny list."""
    write_project_config(workspace_dir, "[container]\ndocker = false\n")
    name = "coi-ks-docker-off"
    try:
        launch(coi_binary, name, cwd=workspace_dir)
        for key in DOCKER_KEYS:
            assert container_config_get(name, key) in ("", "false"), (
                f"{key} should be unset with docker=false"
            )
        assert container_config_get(name, "security.syscalls.deny") == "", (
            "deny list should stay unset without reduce_kernel_surface"
        )
    finally:
        subprocess.run(["incus", "--project", "default", "delete", name, "--force"], timeout=60)


def test_reduce_kernel_surface_hardening(coi_binary, cleanup_containers, tmp_path):
    """Trusted [security] reduce_kernel_surface = true disables Docker support
    and installs the full syscall deny list."""
    cfg = tmp_path / "trusted.toml"
    cfg.write_text("[security]\nreduce_kernel_surface = true\n")
    env = {**os.environ, "COI_CONFIG": str(cfg)}
    name = "coi-ks-hardened"
    try:
        launch(coi_binary, name, env=env)
        for key in DOCKER_KEYS:
            assert container_config_get(name, key) in ("", "false"), (
                f"{key} should be unset under reduce_kernel_surface"
            )
        deny = container_config_get(name, "security.syscalls.deny").split()
        for syscall in DENY_SYSCALLS:
            assert syscall in deny, f"{syscall} missing from deny list: {deny}"
    finally:
        subprocess.run(["incus", "--project", "default", "delete", name, "--force"], timeout=60)


def test_reduce_kernel_surface_strict_adds_perf_event_open(
    coi_binary, cleanup_containers, tmp_path
):
    """Trusted [security] reduce_kernel_surface_strict = true implies the base
    tier (Docker off + full base deny list) and additionally denies
    perf_event_open — the one syscall the strict tier adds."""
    cfg = tmp_path / "trusted.toml"
    cfg.write_text("[security]\nreduce_kernel_surface_strict = true\n")
    env = {**os.environ, "COI_CONFIG": str(cfg)}
    name = "coi-ks-strict"
    try:
        launch(coi_binary, name, env=env)
        for key in DOCKER_KEYS:
            assert container_config_get(name, key) in ("", "false"), (
                f"{key} should be unset under reduce_kernel_surface_strict"
            )
        deny = container_config_get(name, "security.syscalls.deny").split()
        for syscall in DENY_SYSCALLS:
            assert syscall in deny, f"base {syscall} missing under strict tier: {deny}"
        assert "perf_event_open" in deny, (
            f"strict tier must add perf_event_open to the deny list: {deny}"
        )
    finally:
        subprocess.run(["incus", "--project", "default", "delete", name, "--force"], timeout=60)


def test_reduce_kernel_surface_container_boots(coi_binary, cleanup_containers, tmp_path):
    """The hardened deny list must not prevent the container from BOOTING.

    Regression guard for two format bugs that a config-value assertion cannot
    catch (the container has to actually start):
      * the deny value must be \\n-separated (a space-separated value is one
        malformed LXC rule and the container never inits), and
      * each entry must carry an explicit 'errno' action — a bare syscall name
        inherits LXC's default action, which on current Incus is SIGSYS-KILL, so
        init (or systemd's boot helpers calling add_key/bpf) is killed.
    Both ship a green config-only test while breaking every real launch.
    """
    skip_unless_bootable(coi_binary)

    # Hardened: with the deny list applied it must STILL reach RUNNING.
    cfg = tmp_path / "trusted.toml"
    cfg.write_text("[security]\nreduce_kernel_surface = true\n")
    env = {**os.environ, "COI_CONFIG": str(cfg)}
    name = "coi-ks-boot-hardened"
    try:
        launch(coi_binary, name, env=env)
        state = incus_state(name)
        assert state == "RUNNING", (
            f"hardened container did not boot (state={state!r}); the deny list is "
            "likely killing init (missing 'errno' action) or malformed (separator)"
        )
    finally:
        subprocess.run(["incus", "--project", "default", "delete", name, "--force"], timeout=60)


def test_reduce_kernel_surface_strict_container_boots(coi_binary, cleanup_containers, tmp_path):
    """The STRICT tier (base list + perf_event_open) must also boot cleanly.
    perf_event_open was in the set that killed init under the old bare-name
    format; this guards that the strict container reaches RUNNING too."""
    skip_unless_bootable(coi_binary)

    cfg = tmp_path / "trusted.toml"
    cfg.write_text("[security]\nreduce_kernel_surface_strict = true\n")
    env = {**os.environ, "COI_CONFIG": str(cfg)}
    name = "coi-ks-boot-strict"
    try:
        launch(coi_binary, name, env=env)
        state = incus_state(name)
        assert state == "RUNNING", (
            f"strict-hardened container did not boot (state={state!r}); "
            "perf_event_open denial may be killing init instead of returning EPERM"
        )
    finally:
        subprocess.run(["incus", "--project", "default", "delete", name, "--force"], timeout=60)


def test_reduce_kernel_surface_deny_format(coi_binary, cleanup_containers, tmp_path):
    """The deny value must be \\n-separated with an explicit 'errno 1' action on
    every entry — the two properties whose absence (space-separated, bare names)
    made the container fail to boot / SIGSYS-kill init. This asserts the config
    the launch WRITES, so it runs even where the container can't start."""
    cfg = tmp_path / "trusted.toml"
    cfg.write_text("[security]\nreduce_kernel_surface = true\n")
    env = {**os.environ, "COI_CONFIG": str(cfg)}
    name = "coi-ks-deny-format"
    try:
        launch(coi_binary, name, env=env)
        raw = container_config_get(name, "security.syscalls.deny")
        entries = [ln for ln in raw.splitlines() if ln.strip()]
        # Must be newline-separated: one entry per line, and more than one line
        # (a space-separated value would collapse to a single line).
        assert len(entries) == len(DENY_SYSCALLS), (
            f"expected {len(DENY_SYSCALLS)} newline-separated entries, got {entries!r}"
        )
        # Every entry must carry the explicit errno action (never a bare name,
        # which inherits LXC's SIGSYS-kill default on modern Incus).
        for entry in entries:
            assert entry.strip().endswith(" errno 1"), (
                f"deny entry {entry!r} lacks the 'errno 1' action (bare names SIGSYS-kill)"
            )
        # And the syscalls themselves are the base list.
        names = {entry.split()[0] for entry in entries}
        assert names == set(DENY_SYSCALLS), f"deny syscalls {names} != {set(DENY_SYSCALLS)}"
    finally:
        subprocess.run(["incus", "--project", "default", "delete", name, "--force"], timeout=60)


def test_untrusted_docker_reenable_ignored(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """A project config's docker = true must not re-enable nesting that trusted
    config disabled — an untrusted repo must never widen the kernel surface."""
    cfg = tmp_path / "trusted.toml"
    cfg.write_text("[container]\ndocker = false\n")
    env = {**os.environ, "COI_CONFIG": str(cfg)}
    write_project_config(workspace_dir, "[container]\ndocker = true\n")
    name = "coi-ks-untrusted"
    try:
        result = launch(coi_binary, name, env=env, cwd=workspace_dir)
        assert "container.docker" in result.stderr, (
            f"expected the untrusted-downgrade warning naming container.docker; stderr:\n{result.stderr}"
        )
        assert container_config_get(name, "security.nesting") in ("", "false"), (
            "untrusted docker=true must not re-enable security.nesting"
        )
    finally:
        subprocess.run(["incus", "--project", "default", "delete", name, "--force"], timeout=60)
