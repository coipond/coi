# CHANGELOG

## Unreleased

### Changed

- [Change] **Faster start and exit for `coi shell` and `coi run`, especially when reusing a persistent container (#871, #872, #874)** — far fewer Incus and firewall calls per launch, and session state is saved in one step on exit. Rebuild the image (`coi build`) to also get instant `exit` detection.
- [Change] **Faster container boot: cloud-init is disabled in the coi image (#873)** — keep it with `[container.build] cloud_init = true`. Takes effect on the next `coi build`.
- [Change] **Primary name is now `Coi`** — `Coi` (Code on Incus) is the product name and `coi` the command. Cosmetic only.

### Breaking

- [Breaking] **Direct commits and pushes to `main` and `master` are blocked by default** — agents work on a feature branch and open a PR instead; `git pull` keeps working. Turn it off with `[git] protected_branches = []`.

### Bug Fixes

- [Bug Fix] **macOS: no Keychain login hint when `CLAUDE_CODE_OAUTH_TOKEN` is set (#851)** — a long-lived `claude setup-token` token needs no Keychain login.
- [Bug Fix] **Git identity on macOS comes from your Mac's gitconfig, not the Colima/Lima/OrbStack VM's (#853)** — including `include.path` files; on a multi-user Mac only your own home is used.
- [Bug Fix] **Parallel launches of the same workspace no longer collide (#876)** — each launch gets its own container instead of failing or disturbing another launch.
- [Bug Fix] **Containers no longer fail to start at random when many share one git identity (#875)** — the shared `[git] readonly` identity file is no longer rewritten on every launch.
- [Bug Fix] **A failed container start is reported right away (#875)** — with the errors from the container's start log, instead of a 30 s wait and "failed to become ready".
- [Bug Fix] **Attaching to a running restricted-mode container no longer leaves it briefly unfiltered (#872)** — its firewall rules are replaced atomically.
- [Bug Fix] **A failed session save no longer deletes the previous saved copy (#872)**.
- [Bug Fix] **An auto-killed container is always removed (#871)** — it could be left behind, stopped.
- [Bug Fix] **Background and detached sessions stay protected (#869)** — security monitoring and the runtime limit keep running until the container stops, not just while `coi shell` runs.
- [Bug Fix] **Profiles can set `[git] protected_branches` and `[limits.disk] size`** — a profile containing either no longer fails to load.
- [Bug Fix] **A repository's profiles can no longer pull files from your machine into the container** — `context_file` and `context_json_file` are ignored in project profiles, as in project config.
- [Bug Fix] **`[tool] binary` now works** — coi launches the configured executable instead of ignoring it.
- [Bug Fix] **Installer works on fresh container and minimal images** — building from source no longer fails on missing package lists.
- [Bug Fix] **Setting up passwordless sudo can no longer break sudo** — the installer and `coi health --fix` validate the rule before installing it.
- [Bug Fix] **`coi health` accepts its own UID-mapping fix** — it stops reporting the problem once the suggested fix is applied.
- [Bug Fix] **`coi health` no longer misses missing sudo rules** — a recently typed sudo password no longer hides them.
- [Bug Fix] **Security monitor no longer stops containers for everyday commands** — searching code, waiting for a local service, or installing networking tools no longer looks like a reverse shell.
- [Bug Fix] **Large host UIDs (e.g. Google Cloud OS Login) no longer yield an unwritable workspace (#838)** — coi stops with a clear explanation instead.

### Features

- [Feature] **Run commands before the agent starts: `[tool] pre_launch` (#852)** — e.g. `pre_launch = ["claude update"]` keeps the agent current without rebuilding the image.

## 0.13.0 (2026-09-28)

### Changed

- [Change] **Minimum Go version is now 1.26** — building from source now needs Go 1.26+.

### Bug Fixes

- [Bug Fix] **Clean install no longer leaves a half-configured host (#823, #830)** — Incus setup and detection run via sudo, so a fresh session's not-yet-active group can't silently skip initialization; the Incus client config is handed back to the user afterwards.
- [Bug Fix] **Installer prompts read full answers (#831)** — typing "YES" no longer bleeds leftover characters into the next prompt and silently declines it.
- [Bug Fix] **macOS: hint how to bring a Keychain-stored login into the container (#818)** — `coi shell` prints how to bridge a macOS Keychain OAuth token into the container.
- [Bug Fix] **macOS/Colima: tool credentials now seed from the shared Mac home (#817)** — seeds credentials and config from the Mac's shared home when the guest home has none.
- [Bug Fix] **Image build no longer hangs on broken container IPv6** — `coi build` forces IPv4 with bounded apt timeouts so base-dependency installs no longer stall.

### Features

- [Feature] **Frictionless clean-Ubuntu install (#823, #830)** — `curl | bash` on an empty machine now installs Incus from the Zabbly repo, adds you to `incus-admin`, and initializes storage and networking end-to-end, each step consent-gated (`COI_ASSUME_YES=1` for unattended runs).
- [Feature] **`coi build`/`coi shell` work right after install — no re-login (#830)** — coi transparently re-execs under the fresh `incus-admin` group via sudo when the group isn't active yet.
- [Feature] **`coi health --fix` (#826, #832)** — applies safe remediations for failing checks (incus-admin membership, IPv4 forwarding, passwordless nft sudo), with `--dry-run` to preview.
- [Feature] **Storage pool sized to half the disk (#830)** — the installer creates the zfs/btrfs pool at 50% of disk (50GiB floor) instead of a fixed 50GiB.
- [Feature] **`stop` poweroff alias inside containers (#825)** — `stop` now works alongside `close` and `shutdown`.
- [Feature] **Source builds install their own toolchain (#834)** — the installer offers to install git/make/gcc when building from source, with consent.
- [Feature] **Per-mount UID/GID shifting: `shift` on `[[mounts]]` (#604)** — a bind mount can set `shift = true`/`false` to override the session-wide UID-shifting decision.
- [Feature] **Forensics survive an auto-kill: `[monitoring] forensics_on_kill`** — preserves a forensic copy of a container before an auto-kill deletes it. Opt-in.
- [Feature] **Health probes honor the kernel-surface policy** — `coi health` probes boot with the user's `docker`/`reduce_kernel_surface` policy instead of the full surface.
- [Feature] **Clean commit authorship: `[git] strip_attribution` (#788)** — strips AI-injected attribution (`Co-Authored-By`, "Generated with…") from every commit. On by default.
- [Feature] **`[git] readonly` now makes the commit identity truly unoverridable** — pins `GIT_AUTHOR_*`/`GIT_COMMITTER_*` env and re-stamps commits so the locked identity can't be bypassed.
- [Feature] **Kernel attack-surface hardening: `[container] docker` and `[security] reduce_kernel_surface`** — make Docker-in-container a flag and optionally deny risky syscall families (io_uring, bpf, userfaultfd, keyring).
- [Feature] **Stricter kernel-surface tier: `[security] reduce_kernel_surface_strict` (#790)** — opt-in tier that additionally denies `perf_event_open`. Implies `reduce_kernel_surface`.
- [Feature] **Freshness checks in `coi health`** — warns on old kernel build age, disabled CPU mitigations, near/past-EOL distro, and outdated Incus.

## 0.12.0 (2026-09-09)

### Features

- [Feature] **Switch AI tools on the same container via profiles (#708)** — profiles sharing a `[container] session_name` re-enter the same persistent container with a different AI tool.
- [Feature] **Headless "fire and forget" prompt runs (#701)** — `coi run --prompt` runs the agent to completion on a prompt and exits with its status code.
- [Feature] **Cap a container's disk with `[limits.disk] size` (#728)** — bound a container's root filesystem from a profile (needs a CoW pool).
- [Feature] **`--json` on every command** — any command offering `--format text|json` now also accepts `--json` as shorthand.
- [Feature] **`coi tool spec` — launch spec for external orchestrators (#751)** — prints the exact command and environment to run the profile's AI tool in an existing container.
- [Feature] **`coi top` — live per-container resource usage (#707)** — shows per-container CPU, memory, disk, and network usage, busiest first, with per-process drill-down.
- [Feature] **Machine-readable `~/SANDBOX_CONTEXT.json` (#705)** — A structured companion to `SANDBOX_CONTEXT.md` for programmatic consumers; toggle with `[tool] context_json`.
- [Feature] **OpenAI Codex CLI is now supported (#698, thanks @breml)** — `[tool] name = "codex"` launches straight into codex with per-tool model and effort.
- [Feature] **Oh My Pi (`omp`) is now supported (#743, thanks @VIVAAN-DHAWAN)** — `[tool] name = "omp"` launches straight into omp.
- [Feature] **Per-host ports on `[[network.hosts]]`** — scope a single LAN service to specific ports while the rest of the internet stays open.
- [Feature] **`[git] readonly = true`** — Lock the container's git commit identity so the agent can't change who commits are authored by.
- [Feature] **Per-destination ports in `allowed_domains` (#704)** — Allowlist entries take a `:ports` suffix (`"github.com:443"`), so each destination is reachable only on its own ports.
- [Feature] **`[network] dns_servers` and `allowed_ports` (#704)** — Pin which DNS resolvers are reachable and cap outbound ports for tighter egress control.

### Changed

- [Change] **Mount blocks and `env_command_timeout` now work identically in config and profiles (#783)** — `[mounts]` blocks and `env_command_timeout` can be set in global config, project config, and profiles alike.
- [Change] **More reliable container-status checks (#782)** — status comparisons are now case-insensitive everywhere.
- [Change] **Leaner injected sandbox context, ~30% fewer per-session tokens (#718)** — removed duplicated sections from the injected `SANDBOX_CONTEXT.md`.

### Bug Fixes

- [Bug Fix] **`coi build` works on a non-default `[incus] project` (#777, thanks @marshalfevzi)** — building on a non-default project no longer fails with "image not found".
- [Bug Fix] **Sandbox context no longer duplicates in a Windows-edited `CLAUDE.md`/`AGENTS.md` (#674 follow-up)** — CRLF files no longer get a fresh context block appended every session.
- [Bug Fix] **`coi shell` works under kitty and similar terminals (#772)** — terminals exporting `TERM=xterm-kitty` (and `foot`/`rio`/`contour`/`st-…`) no longer fail with "missing or unsuitable terminal".
- [Bug Fix] **`[limits.disk] tmpfs_size` now applies on `coi run` too (#728 follow-up)** — Previously only `coi shell` honored it.
- [Bug Fix] **`permission_mode = "interactive"` keeps Claude Code's auto mode selectable (#764)** — Interactive mode no longer silently disables the in-session Shift+Tab auto-mode toggle.
- [Bug Fix] **Per-tool model/effort reaches external `coi container exec` and reused containers (#744)** — a profile's `[tool.claude] model`/`effort_level` now applies on `coi container exec` and reused containers.
- [Bug Fix] **Security monitor no longer false-freezes a healthy container** — a transient I/O-counter blip is now clamped so it can't trigger an auto-pause.
- [Bug Fix] **Clearer ephemeral-launch retry messages (#716)** — a failed launch no longer blames UID isolation for unrelated causes.
- [Bug Fix] **`[limits.disk] tmpfs_size` now actually resizes `/tmp` (#733)** — the setting previously had no effect; `/tmp` is now sized as configured.
- [Bug Fix] **`coi shell` honors `[container] storage_pool` (#726)** — Interactive sessions now land on the configured pool instead of always the Incus default.
- [Bug Fix] **`coi run` gets the same hardening as `coi shell` (#726 follow-up)** — NIC anti-spoofing, boot-window egress block, IPv6 disable, credential seeding, and git locks now apply to `coi run`.
- [Bug Fix] **Container no longer blocks host suspend (#706, thanks @blegat)** — masked the container's `udisks2` service so it doesn't stop the host from sleeping.
- [Bug Fix] **`install.sh` initializes a fresh Incus correctly (#703)** — it no longer skips `incus admin init` on real hosts.
- [Bug Fix] **Fewer leaked firewall rules (#696)** — `coi container delete` and `coi clean` now fully reclaim a container's firewall rules.
- [Bug Fix] **Writable workspace on OrbStack ≥2.2.2 (#691)** — `coi container start` applies the UID-mapping fix a pre-upgrade container needs.
- [Bug Fix] **`coi health` flags slow non-thin LVM pools (#686)** — a non-thin (or cluster) LVM pool re-copies the whole image every launch; health now warns.

## 0.11.2 (2026-08-11)

### Bug Fixes

- [Bug Fix] **`coi health` detects firewalld zone bloat, and the installer prevents it (#695)** — a new health check flags ballooned firewalld rulesets, and `install.sh` prevents the enrollment.
- [Bug Fix] **Closed the first nft teardown leaks from the #696 audit** — `coi kill`/`shutdown` now remove the container's IPv6 egress block.

## 0.11.1 (2026-08-11)

### Bug Fixes

- [Bug Fix] **Storage-pool driver check hardened (#684 follow-up)** — the `dir`-driver warning is now sourced from structured data and no longer flakes.

### Features

- [Feature] **`[container] session_name` — named sessions that survive workspace moves** — key a session on a name instead of its workspace path. Trusted-scope only.
- [Feature] **`coi health` flags a `dir` storage pool driver (#659, thanks @technicalpickles)** — a `dir` pool re-unpacks the whole image every launch; the health check warns.

### Bug Fixes

- [Bug Fix] **Workspace filesystem is checked before using a `shift=true` mount (#683, thanks @technicalpickles)** — FUSE-backed shares are detected up front and use `raw.idmap`.
- [Bug Fix] **Reusing a stopped persistent container no longer hard-fails on hosts without idmapped mounts (#685, thanks @technicalpickles)** — reuse applies the same UID-mapping fallback fresh launches use.
- [Bug Fix] **Hosts whose kernel can't do idmapped mounts now fall back automatically (#678, thanks @technicalpickles)** — coi converts to `raw.idmap` and retries instead of failing to launch.
- [Bug Fix] **Fixed a doubled `v` in release versions and a broken `coi update` check (#673, thanks @sklarsa)** — `coi update` no longer wrongly reports you're already on the latest version.
- [Bug Fix] **Sandbox context no longer grows `~/.claude/CLAUDE.md` every session (#674)** — the injected block is delimited and rewritten in place, and already-bloated files are healed.

## 0.11.0 (2026-07-29)

### Breaking Changes

- [Breaking] **`model` moved to `[tool.claude] model` and is now actually wired** — set the Claude model under `[tool.claude]`; a root/`[defaults]` `model` is no longer honored.

### Features

- [Feature] **`COI_TIMING_DEBUG=1` reports where a session's startup time went** — a wall-clock timeline of every `incus`/`nft` call, to help diagnose slow launches.
- [Feature] **`[[network.hosts]]` and `coi hosts` (#605)** — give a container fixed `/etc/hosts` name→address entries with matching firewall reachability. Trusted-scope only.
- [Feature] **`[defaults] profile` (#607)** — pick the profile a bare `coi` uses when `--profile` isn't passed. Trusted-scope only.
- [Feature] **`coi close` is an alias for `coi shutdown` (#593)** — mirrors the `close` verb you type inside a container.

### Bug Fixes

- [Bug Fix] **The installer no longer auto-installs ZFS where that can break the system (#666)** — coi uses ZFS only where it's safe and falls back to btrfs otherwise.
- [Bug Fix] **`raw.idmap` is set when `code_uid` matches the host UID and shift is off (#667)** — fixes an unwritable `/workspace` on that configuration.
- [Bug Fix] **Claude Code's dangerous-permissions confirmation is now actually suppressed in sandbox mode (#649)** — non-interactive sandbox startup no longer stalls on the prompt.
- [Bug Fix] **The installer falls back to btrfs when ZFS can't be set up, and skips ZFS on OrbStack (#661)** — containers no longer silently stay on the slow default storage pool.
- [Bug Fix] **`[[network.hosts]]` in allowlist mode honors `allow_local_network_access` for private targets (#605)** — a private-address host entry no longer aborts setup when local-network access is enabled.
- [Bug Fix] **`coi kill` no longer reports a failure when it loses a delete race for a container it killed (#609)** — a container that's already gone now counts as killed.
- [Bug Fix] **`coi run -- <cmd>` runs with `HOME`/`USER` set (#623)** — `~` and `git config --global` work under `coi run`, matching `coi shell`.
- [Bug Fix] **A `code_uid` remap no longer aborts setup when a read-only mount lives under `/home/code` (#608, thanks @technicalpickles)**.
- [Bug Fix] **A persistent container no longer wedges on restart when a protected path was removed from the workspace (#610)** — security mounts are reconciled on restart and re-established for the current workspace.
- [Bug Fix] **Allowlist mode now works with domains behind rotating IP pools (Vertex, Bedrock, most cloud APIs)** — coi resolves allowlisted domains host-side and pins the same addresses in the container's `/etc/hosts`.
- [Bug Fix] **Allowlist firewall refresh/teardown hardened** — the firewall uses atomic named sets and teardown no longer leaks nft sets across sessions.
- [Bug Fix] **Typing `close` no longer mislabels a shutting-down container as "kept running" or leaks a stopped ephemeral container (#616)**, plus a round of shutdown-detection hardening (#597).
- [Bug Fix] **`coi shell --container <missing>` fails fast with a clear error** instead of a misleading 30s timeout.
- [Bug Fix] **`managed-settings.json` lands root-owned and world-readable (#364 follow-up)** — Claude Code no longer fails OAuth when the host UID differs from the container's code user.

### Security

- [Security] **A container in allowlist mode can no longer reach any nameserver** — DNS egress is blocked so it can't learn an address the firewall wasn't already given.
- [Security] **`coi kill` no longer fails when the container is already gone, and now reports why a delete actually failed** instead of a bare exit code.

## 0.10.1 (2026-07-12)

### Features

- [Feature] **Host port publishing: `[ports] pool` and `[[ports.map]]` (#558)** — publish container ports to `localhost:<port>`: `pool = N` identity-mapped ports, `[[ports.map]]` named services.
- [Feature] **`coi list` shows published ports (#558)** — published ports appear in text output and as `published_ports` in `--format json`.

### Bug Fixes

- [Bug Fix] **`coi list --stopped` no longer titles the output "Active Containers:" (#592)** — the heading now follows the status filter.
- [Bug Fix] **`close`/poweroff inside `coi shell` is no longer mislabeled as a normal exit (#597)** — cleanup now waits for the real shutdown and honors the ephemeral/persistent contract.
- [Bug Fix] **`coi tmux capture` / `send` / `list` and `coi attach` no longer target the wrong user's tmux socket (#588)** — they now resolve the `code` user's actual UID instead of root's socket.

## 0.10.0 (2026-07-10)

### Breaking Changes

- [Breaking] **The legacy `claude-on-incus` name is fully retired** — the installer no longer creates the compatibility symlink and removes a leftover one on upgrade.
- [Breaking] **All env-var config overrides removed (`COI_LIMIT_*`, `CLAUDE_ON_INCUS_*`)** — configuration is now config/profiles only; set the equivalent config keys instead.
- [Breaking] **Config-shaped CLI flags removed** — `--image`, `--persistent`, `--tmux`, `--tool`, and others now live in config/profiles; a removed flag prints its replacement key.

### Features

- [Feature] **Generic credential catalog with `[[credentials]]` (#549)** — seed any provider's credential file into the container via a named bundle or ad-hoc host/container file pair.
- [Feature] **`coi list` status filters: `--running`, `--stopped`, `--status <state>` (#578)** — narrow the listing to containers in a given state.
- [Feature] **Workspace run script: `coi run` with no command runs `./coi-run` in the sandbox** — an executable `coi-run` at the workspace root is booted and executed, propagating its exit code.
- [Feature] **`coi run` streams output live and connects piped stdin** — long builds show output as it's produced, and `cat data | coi run -- ./process.sh` works.
- [Feature] **`coi run` now starts security monitoring** — arbitrary commands and run scripts get the same watchers as agent sessions.
- [Feature] **Persistent `coi run` reuses its stopped container** — state actually persists across runs instead of launching a fresh container each time.
- [Feature] **Resume can change a session's persistence via config** — an explicit `[container] persistent` now wins over the resumed session's recorded mode.
- [Feature] **Explicit `--profile` wins over the workspace overlay** — a project `.coi/config.toml` can no longer override the profile's `[container]` settings.
- [Feature] **Built-in `hardened` profile for untrusted repos (#496)** — `--profile hardened` bundles Coi's strongest controls into one preset.
- [Feature] **Non-sudoers mode `[network] use_sudo = false` (#508)** — run without the passwordless-sudo nft rule; restricted/allowlist modes fail closed, open mode works.

### Improvements

- [Enhancement] **Configurable container readiness window** — new `[container] ready_timeout` (default 30s) for slow hosts, also applied to `coi run`.
- [Enhancement] **`coi health` now proves isolation at runtime** — adversarial checks confirm secret masking, host-credential isolation, and network blocking actually hold.
- [Enhancement] **Broadened the `hardened` profile's default secret-mask set (#496)** — also masks `*.p12`, `*.tfvars`, `*.tfstate`, `.git-credentials`, `kubeconfig`, and more.

### Security

- [Security] **Workspace secret-path masking `[security] secret_paths` (#494)** — an opt-in list of workspace globs masked read-only inside the container. Fail-closed and symlink-safe.
- [Security] **`.claude/settings.json` / `settings.local.json` are now mounted read-only** — a contained agent can't plant a `hooks` command a later session would auto-execute.
- [Security] **New `[security] writable_paths` opt-out** — remove specific entries from `protected_paths`; trusted-scope only.
- [Security] **All protection-weakening config fields are now trusted-scope only** — an untrusted project config can only add protections, never disable them.
- [Security] **`coi run` now protects per-worktree git config (#542)** — `.git/worktrees/<name>/config.worktree` is covered on the `coi run` path too, matching `coi shell`.

### Added

- [Feature] **The base image can install only the AI agents you use (#454)** — `[container.build] agents = [...]` installs just the listed agents.
- [Feature] **Git worktrees / bare-repo checkouts now work inside the container, securely (#533)** — Coi mounts the worktree's external gitdir while keeping hook/config RCE-sink files read-only.

### Bug Fixes

- [Bug Fix] **`coi file pull` no longer recursively deletes an existing destination directory** — it now places the pulled entry inside an existing directory, like `cp`/`scp`.
- [Bug Fix] **Container boot no longer hangs when IPv6 is disabled (#548)** — restricted/allowlist mode no longer wedges `network-online.target`.
- [Bug Fix] **Profile schema accepts every field the code supports** — `stale_base_check` and the two monitoring thresholds now validate.
- [Bug Fix] **Profile inheritance no longer drops the parent's `sockets` and `env_commands`**.
- [Bug Fix] **Container git identity is set from your host git config, configurable via `[git]` (#556)** — every tool gets the same commit author; `[git] name`/`email` pin an explicit identity.
- [Bug Fix] **OrbStack is no longer misdetected as Colima/Lima (#553, thanks @technicalpickles)** — fixes an unwritable `/workspace` on OrbStack.
- [Bug Fix] **Virtiofs-backed workspaces no longer break `coi run` (#534)** — disk devices attach before start so the isolation fallback covers them.
- [Bug Fix] **Workspace writes work under Colima/Lima and any host-UID ≠ 1000 (#530)** — `raw.idmap` is set on a UID mismatch so the code user can write `/workspace`.
- [Bug Fix] **Log-rotation threat detection no longer permanently disables itself after a transient read blip**.
- [Bug Fix] **Auto-killed containers no longer leak their per-IP firewall rules**.
- [Bug Fix] **Background monitoring/network diagnostics no longer leak onto the attached terminal (#372)** — diagnostic output goes to the session log instead of corrupting the TUI.
- [Bug Fix] **Monitoring no longer crashes at session start when the GTFOBins detection DB is present (#505)**.
- [Bug Fix] **opencode is installed for the host CPU architecture instead of always x86_64 (#506)** — fixes arm64 hosts.

## 0.9.0 (2026-06-17)

### Security

- [Security] **Out-of-workspace mounts from an untrusted project config now require `coi trust`** — such mounts are dropped unless approved with `coi trust`.
- [Security] **`coi file pull` / session-state save no longer recreate container symlinks or special files on the host** — closes a symlink-extraction host-tampering vector.
- [Security] **Stale per-IP firewall rules are purged before applying policy** — closes a DHCP-lease-reuse egress bypass.
- [Security] **`coi clean --orphans` now also removes orphaned IPv6 drop rules**.
- [Security] **Allowlist mode scopes egress to TCP/UDP + rate-limited ICMP** — closes ICMP-tunnel and raw-IP covert channels to allowed hosts.
- [Security] **The remaining git config/attribute sinks are now read-only** — `.git/info/attributes`, `.git/config.worktree`, and per-worktree config are locked (they could run host commands).
- [Security] **Workspace `.coi/` is now read-only inside the container** — an agent can no longer plant project config or profiles applied on the next launch.
- [Security] **An untrusted project config can no longer weaken network isolation** — settings that would expose metadata or private networks are dropped; only strengthening values honored.
- [Security] **The default `coi` image builds from the embedded build script, not the workspace copy** — an agent can't poison `coi-default` by editing `build.sh` in the workspace.
- [Security] **Bridge NIC anti-spoofing and port isolation** — blocks source IP/MAC spoofing and container-to-container lateral movement.
- [Security] **IPv6 egress is now enforced host-side** — replaces a container-reversible in-container sysctl; fails closed in restricted/allowlist mode.
- [Security] **Boot-time network block now fails closed in restricted/allowlist mode**, and covers persistent-container restarts so planted startup scripts can't get an unrestricted boot window.

### Features

- [Feature] **Mint short-lived secrets at session start with `[defaults.env_commands]`** — maps an env var to a host command whose stdout is injected at launch. Trusted-scope only.
- [Feature] **Forward arbitrary host Unix sockets into the container with `[[sockets]]`** — generalizes SSH agent forwarding to any host socket. Untrusted sockets require `coi trust`.

### Bug Fixes

- [Bug Fix] **`coi update` on a dev build no longer fails or hides its `--force` guidance when the GitHub API is unavailable** — it refuses offline-safely before any network call.
- [Bug Fix] **`DirExists`/`FileExists`/`Chown` now handle container paths with spaces or shell metacharacters** — args are passed verbatim instead of through the shell.
- [Bug Fix] **Bridge firewall rules are no longer removed when `incus list` output can't be parsed** — the default is now to keep rules.
- [Bug Fix] **`coi run` network setup now respects Ctrl+C** — SIGINT is honored during network setup.
- [Bug Fix] **`max_duration` remaining-time now reports the actual time left** instead of always the full duration.
- [Bug Fix] **Suspicious-exec pattern matching is now case-insensitive**.
- [Bug Fix] **Allowlist firewall rules no longer momentarily drop to zero during a DNS refresh** — the rule set is never empty mid-transition, closing a brief unrestricted window.
- [Bug Fix] **Session metadata no longer corrupts on paths or profile names with special characters** — fixes broken `coi list` / `--resume` for such workspaces.

### Security

- [Security] **Sigma `linux/process_creation` rules as a second detection source** — `coi update sigma` sparse-clones community Sigma rules the exec monitor loads.
- [Security] **Runtime-loadable exec pattern database** — the exec watcher loads GTFOBins patterns from `~/.coi/gtfobins/` via `coi update patterns`.
- [Security] **Unified `coi update`** — updates the binary and the pattern database together; `coi update core` / `coi update patterns` for granular control.
- [Security] **Sensitive-file access monitored host-side via fanotify** — credential reads and persistence writes raise HIGH/CRITICAL threats, tamper-resistant from inside the container.
- [Security] **Network, UDP, and process monitoring read host-side from the container's namespace/cgroup** — an attacker inside can no longer hide connections or processes (#430, #432, #428).
- [Security] **Fork-bomb and process-spawn-rate detection** — raises CRITICAL when process count or spawn rate exceeds a configurable threshold.
- [Security] **Host-side auth.log / syslog monitoring** — detects failed logins, invalid users, and sudo/su privilege-escalation attempts (WARNING/HIGH threats).
- [Security] **Real-time process-exec monitoring via PROC_EVENTS** — flags reverse shells, netcat `-e`, socket one-liners, and root privilege escalation at exec time.
- [Security] **UID-namespace isolation per container** (`security.idmap.isolated`) — eliminates cross-container UID overlap on shared hosts.
- [Security] **Docker bridge CIDR isolation** — moves the docker0 bridge and network pool to `172.30/172.31` to avoid conflicts with corporate VPNs/cloud subnets.

### Improvements

- [Enhancement] **`coi profile create default` scaffolds a documented starter config** — writes a fully-commented `config.toml` with every value commented out. Never overwrites an existing config.
- [Enhancement] **Stale base image detection** — `coi shell`/`coi run` warn when a custom image predates its rebuilt base. Resolves #456.
- [Enhancement] **`coi build --all`** — builds every profile with a `[container.build]` section, base image first. Resolves #455.
- [Enhancement] **`coi version --format json`** — machine-readable version output.
- [Enhancement] **`use_tmux` config option** — set `use_tmux = false` in `[shell]` instead of passing `--tmux=false` every time. Resolves #399.
- [Enhancement] **Base image downloaded directly from Canonical's CDN (#388)** — `coi build` fetches Ubuntu from `cloud-images.ubuntu.com`; override via `[container.build] base`.
- [Enhancement] **Interactive build prompt when the image is missing** — `coi shell`/`coi run` offer to build inline instead of failing; non-interactive use is unchanged.
- [Enhancement] **Sudo ownership guidance in SANDBOX_CONTEXT.md (#368)** — tells the tool to `chown` workspace files after `sudo`, which otherwise leaves them root-owned.

**Note:** `coi health --format json` renamed several keys in this release (`firewall`→`nft`, `orphaned_firewall_rules`→`orphaned_nft_rules`, `bridge_firewalld_zone`→`bridge_forward_rules`) as part of the firewalld→nftables naming cleanup — update any consumers.

### Bug Fixes

- [Bug Fix] **Disk I/O limits now work** — applied as device-level keys on the root disk (the correct Incus API) instead of container-level config.
- [Bug Fix] **Negative and zero `max_duration` values are now rejected**.
- [Bug Fix] **`coi run` now enforces `max_duration` at runtime** — previously only `coi shell` honored it.
- [Bug Fix] **`coi shell --resume` now works when the container is already Running (#413)** — fixes a post-reboot "slot already in use" failure.
- [Bug Fix] **Error messages no longer suggest removed CLI flags** — they now point at the `config.toml` settings that replaced them (#398).
- [Bug Fix] **Allowlist IP-refresh logs no longer pollute the terminal** — background refresh output goes to a log file (#372).
- [Bug Fix] **`poweroff` / `close` now work cleanly in Ubuntu 24.04 containers** — bypasses a systemd-logind transaction conflict; also fixes the `unable to resolve host` warning before sudo.
- [Bug Fix] **Clearer error when the incus-admin group isn't active yet** — tells you to log out/in or run `newgrp incus-admin` (#383).
- [Bug Fix] **Escape key now works in nested tmux sessions** — ships `escape-time 10` so Esc reaches opencode/vim promptly (#378).
- [Bug Fix] **Effort level no longer locked when not configured** — Coi only injects `CLAUDE_CODE_EFFORT_LEVEL` when `effort_level` is set, so you can change it mid-session (#376).
- [Bug Fix] **`coi run` now applies network isolation and SSH agent forwarding from config** — previously it ignored `[network]`/`[ssh]` (#373).
- [Bug Fix] **Fixed a double `v` prefix (`vv0.8.x`) in the version display**.
- [Bug Fix] **Session data no longer lost on `sudo poweroff`** — the session-state save retries once the container has stopped instead of failing on a transient SFTP error (#397).
- [Bug Fix] **Incus errors now surface stderr** — e.g. `Error: Instance not found` instead of a bare `exit status 1` (#276).

### Features

- [Feature] **`coi audit` — live threat-event streaming (#362, contributed by @ChrisJr404)** — streams container file/network/exec events as JSON Lines for piping into a SIEM or `jq`.

## 0.8.1 (2026-05-07)

### Improvements

- [Enhancement] **Stronger git identity discovery instructions in SANDBOX_CONTEXT.md** — the injected hints now mandate discovering a real identity before the first commit and forbid fabricated ones.

### Bug Fixes

- [Bug Fix] **Suppress Claude Code auto-mode / bypassPermissions prompts in sandbox (#364)** — sandbox startup no longer stalls on the interactive auto-mode confirmation.
- [Bug Fix] **Sandbox settings injection is now pure Go instead of Python (#351, #355)** — merging sandbox settings no longer depends on `python3` in the container.
- [Bug Fix] **Removed the `sg` dependency (#349)** — coi runs `incus` directly, fixing breakage on distros where `sg` is root-only.
- [Bug Fix] **Secure env-var forwarding in tmux sessions (#352, contributed by @SimonArnu)** — forwarded variables are passed via tmux's environment instead of inline `export`, so secrets don't show in `ps`.

### Features

- [Feature] **Profile auto-resume** — `coi shell --resume` restores the profile the session was created with; passing `--profile` overrides it. (#342)
- [Feature] Added `close` command inside containers as an alias for `poweroff`, a safe alternative to prevent accidental host shutdowns.
- [Feature] **Better git auth hints in SANDBOX_CONTEXT.md** — adds a `Git Configuration` section guiding tools to prefer SSH and derive commit identity from the SSH key. (#337)
- [Feature] **Git identity guard** — containers set `user.useConfigOnly true` so git refuses commits until a real identity is configured.

## 0.8.0 (2026-04-16)

### Breaking Changes

- [Breaking] **Host-side immutable protection for protected paths** — Coi `chattr +i`'s protected paths on the host before start, closing the `unshare -m` + `umount` bypass.
- [Breaking] **Default image renamed `coi` → `coi-default`** — run `coi build` after updating.
- [Breaking] **Removed `coi build custom`** — build custom images through profiles instead.
- [Breaking] **Auto-build on missing image removed** — `coi shell`/`coi run` now error and tell you to `coi build` first.
- [Breaking] **Many CLI flags removed in favor of config/profiles** — `--mount`, `--env`, `--network`, `--ssh-agent`, all `--limit-*`, and others now live in `config.toml`.
- [Breaking] **Project config moved from `.coi.toml` to `.coi/config.toml`** (#251) — only `~/.coi/` and `./.coi/` are scanned now.
- [Breaking] **New `[container]` config section** consolidates image, persistence, storage pool, and build settings (#302).
- [Breaking] **Health check `incus_storage_pool` → `incus_storage_pools`** — now a per-pool map in JSON output.
- [Breaking] **`coi resume` renamed to `coi unfreeze`** — avoids confusion with `coi shell --resume`.

### Features

- [Feature] **Container aliases** — `[container] alias = "myproject"` lets you `coi shell/attach/kill/unfreeze myproject` from any directory (#304).
- [Feature] **Per-profile storage pool** — `[container] storage_pool` routes a project to a specific Incus pool (#302).
- [Feature] **Storage-pool visibility** — `coi list` shows POOL, `coi health` reports per-pool usage, and `coi clean --pools` removes containers in unreferenced pools.
- [Feature] **Guest API disabled by default** (`security.guestapi=false`) — stops containers querying host source paths.
- [Feature] **Profiles** — self-contained profile directories with an embedded built-in `default` and inheritance via `inherits`. Part of #114.
- [Feature] **Read-only mount support** — `readonly = true` on a mount entry shares host dirs without letting the container modify them (#260).
- [Feature] **Self-update command (`coi update`)** — downloads the latest release, verifies its SHA256, and atomically replaces the binary.
- [Feature] **Build configuration in project config** — `[container.build]` defines how to build a custom image so `coi build` builds it automatically (#251).
- [Feature] **Host timezone inheritance** — containers inherit the host timezone by default; configurable via `[timezone]` (`host`/`fixed`/`utc`) (#236).
- [Feature] **Auto-inject sandbox context into AI tool sessions** — `~/SANDBOX_CONTEXT.md` is loaded into each tool's native context. Opt out with `[tool] auto_context = false` (#243).
- [Feature] **Expanded container toolset with mise-managed runtimes** — adds `fd`, `bat`, `tree`, `strace`, `lsof`, `sqlite3`, DB clients, and mise-managed Python/pnpm/TypeScript/tsx.
- [Feature] **SSH agent forwarding** — `[ssh] forward_agent = true` bridges the host `SSH_AUTH_SOCK` into the container.
- [Feature] **Environment variable forwarding** — `forward_env = [...]` reads named host vars at session start without storing them in config.
- [Feature] **TTL-aware DNS refresh for allowlist mode** — re-resolves allowed domains on their actual DNS TTL (60s floor) so rotating CDN/cloud IPs stay reachable.
- [Feature] **Safety guards and version checks** — a privileged-container hard block, security-posture health check, and minimum-version checks for Incus and nftables (#237, #212, #214).
- [Feature] **Image compression flag** — `--compression` on `coi build` / `coi image publish` (thanks @rominf, #233).
- [Feature] **Auto-trust mise config files in the workspace** — no manual `mise trust` needed inside the container (#328).

### Bug Fixes

- [Bug Fix] **Strengthened sandbox context prompt to reduce unnecessary permission requests** — an explicit "Autonomous Operation" section tells the AI it has full autonomy in its sandbox (#308).
- [Bug Fix] **`coi shell` cleanup no longer prints a scary "Failed to save session data" warning when the tool config dir doesn't exist** — a missing directory is treated as benign.
- [Bug Fix] **`coi shell` now runs custom `[container.build]` images as `code`, not root** — the user is probed at runtime instead of matched by image alias.
- [Bug Fix] **`coi shell` no longer truncates long outputs to 2000 lines** — the default image ships `history-limit 50000` (#312).
- [Bug Fix] **Non-existent protected paths are now materialized before mounting** — closes a host-persistence attack via the writable workspace mount.
- [Bug Fix] **CLI no longer dumps usage/help after output on a non-zero exit** (e.g. degraded `coi health`) (#287).
- [Bug Fix] **`coi health` no longer shows negative free space on a fresh Incus pool** — storage unit suffixes (MiB/GiB/…) are normalized (#285).
- [Bug Fix] **Incus bridge outside the firewalld trusted zone is now auto-fixed at runtime** — no more 30s "Waiting for network…" hang with only a copy-paste hint (#220).
- [Bug Fix] **Build-from-source now fails with actionable messages** when the Go toolchain or `libsystemd-dev` is missing (including the `sudo` strips-PATH pitfall).
- [Bug Fix] **Profile operations no longer mutate global config** (pointer aliasing), and profile inheritance now merges `additional_protected_paths` instead of replacing them.
- [Bug Fix] **`attach` now respects the global `--workspace` flag**, and `list`/`info`/`clean`/`persist`/`monitor`/`health` now respect `--profile` (they previously reloaded config and dropped it).
- [Bug Fix] **`coi run` and 62 other call sites now clean up on non-zero exit** — replaced `os.Exit()` with cobra error returns so deferred cleanup runs.
- [Bug Fix] **IPv6 bypass of all network isolation rules closed** — IPv6 is disabled in the container in restricted/allowlist modes.
- [Bug Fix] **Allowlist refresh no longer leaves an unprotected window** — new rules are applied before old ones are removed.
- [Bug Fix] **`StopGraceful` semantics no longer inverted** — a graceful stop is no longer a force-stop; adds a 5s force-stop escalation.
- [Bug Fix] **Dynamic UID mapping for workspace mounts** — `raw.idmap` maps a mismatched host UID to the code user, fixing "Permission denied" on non-1000 hosts and CI (#226).
- [Bug Fix] **IPv4 preferred for Claude CLI install in containers** — avoids IPv6 timeouts/403s (#224).
- [Bug Fix] **Raw-iptables fallback for Docker's FORWARD DROP without firewalld** — fixes a "Waiting for network…" hang when Docker is installed (#83).
- [Bug Fix] **`install.sh` now works correctly under `curl | bash`** — interactive detection and `read` use `/dev/tty` (#215, #222, thanks @dgrant).

### Enhancements

- [Enhancement] **`coi update` restores `cap_linux_immutable` after replacing the binary** (or prints the manual `setcap` command).
- [Enhancement] **`coi profile create` / `edit` / `delete`** — manage profiles from the CLI instead of hand-editing config (#114).
- [Enhancement] **Standardized CLI table output** across `snapshot list`, `image list`, `profile list`, `tmux list`, with `--format text|json` (#141).
- [Enhancement] **`coi monitor` auto-detects the container** from the workspace, with a `--workspace` override (#112).
- [Enhancement] **Expanded env-scanning detection** — catches Python/Node/Ruby/awk env reads and `/proc/*/environ` access via `strings`/`xxd`/`hexdump`.

### Improvements

- [Improvement] **Installer detects active ufw before installing firewalld** — avoids container-networking breakage when both manage netfilter; adds a `ufw_conflict` health check (#281).
- [Improvement] **`-a`/`--all` and `-f`/`--force` short flags** added across the relevant commands.
- [Improvement] **`profile show` renamed to `profile info`** (old verb kept as a hidden alias); new `container info` / `image info` subcommands; `coi images` removed (use `coi image list`).
- [Improvement] **Installer auto-initializes Incus** (`incus admin init --auto`) on fresh installs and quiets its raw command output.
- [Improvement] **Profiles loaded from both `~/.coi/profiles/` and `./.coi/profiles/`** — a name defined in both is a hard error.

## 0.7.0 (2026-03-10)

### Bug Fixes

- [Fix] **opencode session resume in ephemeral mode** — `--continue` now resumes correctly, with the SQLite session DB persisted on the host mount across container recreation (#196). Also fixed opencode session detection (#183), XDG config location (#158), interactive permission mode (#186), and the install URL (#157).
- [Fix] **`coi build --force` works from any directory** — build assets are embedded via `//go:embed` (#176).
- [Bug Fix] **Docker Compose now works inside session containers** — nesting/sysctl-intercept flags are set before first boot on the `coi shell` path, and `ip_unprivileged_port_start` is pre-set to avoid an AppArmor-blocked write (#187).
- [Bug Fix] **Docker works without `sudo` for the `code` user** — the socket is created with group `code` (#134).
- [Bug Fix] **Persistent-session resume reuses the stopped container** instead of creating a fresh one, so system-level changes aren't lost (#190).
- [Bug Fix] **Container user UID/GID remapped for a non-default `code_uid`** — fixes "Permission denied" / "I have no name!" (#166).
- [Bug Fix] **Config merge no longer silently drops boolean settings** — security-critical defaults (`block_private_networks`, `auto_kill_on_critical`, …) survive multi-layer merges (converted to `*bool`).
- [Bug Fix] **`[incus]` config values are now actually applied** to Incus command execution (`project`, `group`, `code_uid`, `code_user`).
- [Bug Fix] **`settings.json` merge preserves the user's `env` section** (deep merge) — no longer drops e.g. AWS Bedrock vars.
- [Bug Fix] **`preserve_workspace_path` honored everywhere** — `coi attach`/`run`/`container exec` and protected-path mounts use the dynamic workspace path, with guards against mounting over system dirs.
- [Bug Fix] **`/tmp` exhaustion no longer hangs agents silently** — `/tmp` is backed by the root disk by default (opt-in RAM tmpfs via `tmpfs_size`), with auto-cleanup of stale files (#135).
- [Bug Fix] **NFT/firewall rule cleanup completed across all termination paths** — `coi shutdown`, `coi container delete`, `coi kill`, and responder auto-kill all clean firewall + NFT-monitoring rules and veth zone bindings, fixing rule accumulation that could hang the system (#119, #130). RFC1918 host traffic is no longer flagged in open mode.
- [Bug Fix] **NFT monitor / security-monitoring output no longer corrupts the TUI or spams alerts** — errors route through `OnError`, threats dedupe in a 30s window, and only pause/kill actions print to stderr.
- [Bug Fix] **Cross-device / symlink handling when saving session data** — `PullDirectory` falls back to recursive copy on `EXDEV` and recreates symlinks (thanks @psaab, #106).

### Features

- [Feature] **Security Monitoring System** — always-on, host-side monitoring detects reverse shells, data exfiltration, secret scanning, and unexpected network connections, escalating log → alert → pause → kill with a JSONL audit log. `coi monitor` shows a live dashboard. Addresses #112.
- [Feature] **nftables-based network monitoring** — kernel-level, tamper-resistant visibility into all container network activity (including short-lived and blocked connections), flagging metadata-endpoint access, suspicious ports, and allowlist violations.
- [Feature] **Large-write and disk-space detection** — flags large filesystem writes (exfil vector) and `/tmp` above 80%.
- [Feature] **opencode support** — opencode is a supported tool (`[tool] name = "opencode"` / `coi shell --tool opencode`), installed in the base image, with permission-bypass config and `--continue` resume (#117).
- [Feature] **Configurable permission mode** — `[tool] permission_mode` toggles `bypass` (default) vs `interactive` (human-in-the-loop), for Claude and opencode.
- [Feature] **Configurable protected paths** — `[security]` `protected_paths` / `additional_protected_paths` / `disable_protection` control the read-only set (defaults: `.git/hooks`, `.git/config`, `.husky`, `.vscode`); symlinks rejected.
- [Feature] **`preserve_workspace_path`** — mount the workspace at its host absolute path instead of `/workspace`, so path-relative session data persists (#108).
- [Feature] **Claude effort-level config** — `[tool.claude] effort_level` prevents interactive prompts in autonomous sessions.
- [Feature] **`coi unfreeze`** — unfreeze a security-paused container (or all frozen Coi containers).
- [Feature] **`--tool` flag for `coi shell`** — override the configured tool for one session.
- [Feature] **New health checks** — Incus storage pool, container connectivity (real in-container DNS/HTTP test), and network restriction (verifies restricted mode actually blocks private IPs) (#102).
- [Feature] **`coi container list` and `-t/--tty` for `coi container exec`** — low-level listing and PTY allocation for programmatic/interactive use (#123, #124).
- [Feature] **Base image adds ripgrep and fzf**.

## 0.6.0 (2026-02-02)

### Bug Fixes

- [Bug Fix] **`settings.json` is now merged, not overwritten** — user config (AWS Bedrock creds, env vars, custom settings) is preserved when sandbox permissions are added (#76).
- [Bug Fix] **`coi list --all` session listing fixed** — the Saved Sessions section always appears, and detection is tool-agnostic via `tool.ConfigDirName()` instead of hardcoded `.claude` (#81).
- [Bug Fix] **Image-build DNS auto-fix broadened** — handles localhost/`127.x.x.x` and missing nameservers, fixing a "Waiting for network…" hang (#83).

### Features

- [Feature] **Resource and time limits** — `[limits]` controls CPU, memory, disk I/O, max processes, and a `max_duration` after which the container is auto-stopped (#71).
- [Feature] **`coi health` command** — verifies dependencies (Incus, permissions, image age, bridge, firewalld, storage, …) with `--format json` and exit codes 0/1/2.
- [Feature] **Firewalld-based network isolation** — replaces OVN/OVS with firewalld FORWARD-chain rules scoped by container IP, working on any standard Incus bridge.
- [Feature] **Automatic Docker/nested-container support** — sets the nesting/syscall-intercept flags so Docker works out of the box.
- [Feature] **Automatic Colima/Lima detection** — disables UID shifting inside those VMs (which handle mapping themselves); manual override via `[incus] disable_shift`.
- [Feature] **AWS Bedrock validation for Colima/Lima** — fails fast with actionable errors when the Bedrock/`.aws` setup is incomplete (#76).
- [Feature] **`coi snapshot`** — create/list/restore/delete container snapshots (optionally stateful) for checkpoint/rollback workflows (#72).
- [Feature] **`coi persist`** — convert running ephemeral containers to persistent (`--all`, `--force`).
- [Feature] **`coi list` shows IPv4 addresses** for running containers (#66).

### Enhancements

- [Enhancement] **Claude CLI now installed via the official native installer** instead of the deprecated npm package; rebuild the base image with `coi build --force` (#82).
- [Enhancement] **macOS/Colima docs and UX** — clearer setup and an open-mode-without-firewalld warning.

## 0.5.2 (2026-01-19)

### Bug Fixes

- [Bug Fix] Fix version mismatch in released binaries - Version 0.5.1 was incorrectly showing as 0.5.0 due to hardcoded version string in source code.

### Enhancements

- [Enhancement] Implement dynamic version injection via ldflags during build - Version is now automatically set from git tags at build time instead of being hardcoded in source code.
- [Enhancement] Add version verification step in GitHub Actions release workflow - Build process now validates that the binary version matches the git tag before creating releases, preventing future version mismatches.
- [Enhancement] Update Makefile to inject version from git tags using `git describe --tags --always --dirty`, with fallback to "dev" for local builds without tags.

### Technical Details

Version injection implementation:
- **Source code**: Changed `Version` from `const` to `var` with default value "dev" in `internal/cli/root.go`
- **Build system**: Added `VERSION` variable and `LDFLAGS` to Makefile for dynamic version injection
- **Release workflow**: Pass `VERSION` environment variable to build step and verify binary version matches expected tag
- **Verification**: Release workflow now extracts version from built binary and compares against git tag, failing build on mismatch

## 0.5.1 (2026-01-17)

### Features

- [Feature] Auto-detect and fix DNS misconfiguration during image build. On Ubuntu systems with systemd-resolved, containers may receive `127.0.0.53` as their DNS server, which doesn't work inside containers. Coi now automatically detects this issue and injects working public DNS servers (8.8.8.8, 8.8.4.4, 1.1.1.1) to unblock the build process.
- [Feature] Built images now include conditional DNS fix that activates only when DNS is misconfigured, ensuring containers work regardless of host Incus network configuration.
- [Feature] Allowlist mode now supports raw IPv4 addresses in addition to domain names. Users can add entries like `8.8.8.8` directly to `allowed_domains` without needing to resolve them.

### Bug Fixes

- [Bug Fix] Suppress spurious "Error: The instance is already stopped" message during successful image builds. The error was appearing during cleanup when the container was already stopped by the imaging process. Now checks if container is running before attempting to stop it.
- [Bug Fix] Fix spurious "Error: The instance is already stopped" message during `coi run --persistent` cleanup. When a persistent container stopped itself after command completion, the cleanup tried to stop it again, causing spurious errors. Now checks if container is running before attempting to stop it.
- [Bug Fix] Fix potential race condition in `coi shutdown` where force-kill could attempt to stop an already-stopped container if graceful shutdown completed during the timeout window. Now checks if container is still running before attempting force-kill.

### Documentation

- [Docs] Added Troubleshooting section to README with DNS issues documentation and permanent fix instructions.

### Testing

- [Testing] Added integration test `tests/build/no_spurious_errors.py` to verify no spurious errors appear during successful builds
- [Testing] Added integration test `tests/run/run_persistent_no_spurious_errors.py` to verify no spurious errors during persistent run cleanup
- [Testing] Added integration test `tests/shutdown/shutdown_no_spurious_errors.py` to verify no spurious errors during shutdown with timeout
- [Testing] Added integration test `tests/build/build_dns_autofix.py` to verify DNS auto-fix works during builds with misconfigured DNS
- [Testing] Added unit test `internal/network/resolver_test.go` for raw IPv4 address support in allowlist mode

## 0.5.0 (2026-01-15)

**Major architectural refactoring to support multiple AI coding tools**

This release introduces a comprehensive tool abstraction layer that allows code-on-incus to support multiple AI coding assistants beyond Claude Code. The refactoring was completed in three phases (Phase 1-3) with minimal user-facing changes.

### Breaking Changes

**Session Directory Structure:**
- Old: `~/.coi/sessions/<session-id>/`
- New: `~/.coi/sessions-claude/<session-id>/` (for Claude)
      `~/.coi/sessions-aider/<session-id>/` (for Aider, future)
      etc.

**Migration:** Old sessions in `~/.coi/sessions/` will not be automatically migrated. You can manually move session directories if needed, or start fresh sessions.

### Features

**Phase 1: Tool Abstraction Layer (#18)**
- [Feature] New `tool.Tool` interface for AI coding tool abstraction
- [Feature] `ClaudeTool` implementation with session discovery and command building
- [Feature] Tool registry system for registering and retrieving tools
- [Feature] Config-based tool selection via `tool.name` configuration option

**Phase 2: Runtime Integration (#19)**
- [Feature] Tool abstraction wired throughout runtime (shell, setup, cleanup)
- [Feature] Tool-specific configuration directory handling (e.g., `.claude`, `.aider`)
- [Feature] Tool-specific sandbox settings injection
- [Feature] Support for both config-based and ENV-based tool authentication

**Phase 3: Tool-Specific Session Directories (#20)**
- [Feature] Separate session directories per tool (`sessions-claude`, `sessions-aider`)
- [Feature] Session isolation between different AI tools
- [Feature] Extensible architecture for adding new tools without affecting existing sessions

### Configuration

New `tool` configuration section:
```toml
[tool]
name = "claude"          # AI coding tool to use (currently supports: claude)
# binary = "claude"      # Optional: override binary name
```

### Code Quality & Testing

- [Enhancement] Added golangci-lint to CI with essential linters
- [Enhancement] Added race detector to Go unit tests (`-race` flag)
- [Enhancement] Added test coverage reporting (local, no third-party uploads)
- [Enhancement] Auto-formatted entire codebase with gofmt/gofumpt
- [Enhancement] Removed unused code and functions

### Documentation

- [Documentation] Updated README from "claude-on-incus" to "code-on-incus"
- [Documentation] Rebranded to emphasize multi-tool support
- [Documentation] Added "Supported AI Coding Tools" section
- [Documentation] Updated all CLI help text to be tool-agnostic
- [Documentation] Noted Claude Code as default tool with extensibility for others

### Technical Details

**Tool Interface:**
```go
type Tool interface {
    Name() string                  // "claude", "aider", "cursor"
    Binary() string                // binary name to execute
    ConfigDirName() string         // config directory (e.g., ".claude")
    SessionsDirName() string       // sessions directory name
    BuildCommand(...) []string     // build CLI command
    DiscoverSessionID(...) string  // find session ID from state
    GetSandboxSettings() map[string]interface{}  // sandbox settings
}
```

### New Files
- `internal/tool/tool.go` - Tool abstraction interface and Claude implementation
- `internal/tool/registry.go` - Tool registry for factory pattern
- `internal/tool/tool_test.go` - Comprehensive tool abstraction tests
- `internal/session/paths.go` - Tool-specific session directory helpers

### Modified Files
- `internal/cli/shell.go` - Tool-aware session management
- `internal/cli/list.go` - Tool-specific session listing
- `internal/cli/info.go` - Tool-specific session info
- `internal/cli/clean.go` - Tool-specific session cleanup
- `internal/cli/root.go` - Updated CLI descriptions to be tool-agnostic
- `internal/cli/attach.go` - Generic "AI coding session" terminology
- `internal/cli/build.go` - Multi-tool support noted
- `internal/cli/tmux.go` - Generic session references
- `internal/session/setup.go` - Tool-aware setup logic
- `internal/session/cleanup.go` - Tool-aware cleanup logic
- `internal/config/config.go` - Added ToolConfig section
- `.golangci.yml` - Comprehensive linter configuration
- `.github/workflows/ci.yml` - Added golangci-lint, race detector, coverage
- `README.md` - Rebranded to emphasize multi-tool support

### Future Tool Support

The architecture now supports adding new AI coding tools with minimal changes:
1. Implement the `Tool` interface
2. Register in `tool/registry.go`
3. Tool-specific sessions automatically isolated

Example tools that can be added:
- Aider - AI pair programming assistant
- Cursor - AI-first code editor
- Any CLI-based AI coding assistant

## 0.4.0 (2026-01-14)

Add comprehensive network isolation with domain allowlisting and IP-based filtering, enabling high-security environments where containers can only communicate with approved domains.

### Features
- [Feature] Domain allowlisting mode - Restrict container network access to only approved domains
- [Feature] DNS resolution with automatic IP refresh (every 30 minutes by default)
- [Feature] IP caching for DNS failure resilience and container restarts
- [Feature] Background goroutine for periodic IP refresh without container restart
- [Feature] Per-profile domain allowlists for different security contexts

### Enhancements
- [Enhancement] New `allowlist` network mode alongside existing `restricted` and `open` modes
- [Enhancement] Always block RFC1918 private networks in allowlist mode
- [Enhancement] Persistent IP cache at `~/.coi/network-cache/<container>.json`
- [Enhancement] Graceful DNS failure handling with last-known-good IPs
- [Enhancement] Comprehensive logging for DNS resolution and IP refresh operations
- [Enhancement] Dynamic ACL recreation for IP updates without container restart

### Configuration
- `network.mode = "allowlist"` - Enable domain allowlisting
- `network.allowed_domains = ["github.com", "api.anthropic.com"]` - List of allowed domains
- `network.refresh_interval_minutes = 30` - IP refresh interval (default: 30, 0 to disable)

### Documentation
- [Documentation] Updated README.md with network isolation modes and configuration
- [Documentation] Added DNS failure handling and IP refresh behavior explanations
- [Documentation] Documented security limitations and best practices
- [Documentation] Simplified networking documentation for better accessibility

### Technical Details
Allowlist implementation:
- **DNS Resolution**: Resolves domains to IPv4 addresses on container start
- **ACL Structure**: Default-deny with explicit allow rules for resolved IPs
- **IP Refresh**: Background goroutine checks for IP changes every 30 minutes
- **Cache Format**: JSON file with domain-to-IPs mapping and last update timestamp
- **Graceful Degradation**: Uses cached IPs on DNS failures, only fails if no IPs ever resolved
- **ACL Update**: Full ACL recreation (delete + create + reapply) for IP changes (~100ms network interruption)

### New Files
- `internal/network/cache.go` - IP cache persistence manager
- `internal/network/resolver.go` - DNS resolver with caching and fallback
- `tests/network/test_allowlist.py` - Integration test framework for allowlist mode

### Modified Files
- `internal/config/config.go` - Added `AllowedDomains`, `RefreshIntervalMinutes`, `NetworkModeAllowlist`
- `internal/network/acl.go` - Added `CreateAllowlist()`, `buildAllowlistRules()`, `RecreateWithNewIPs()`
- `internal/network/manager.go` - Added `setupAllowlist()`, `startRefresher()`, `stopRefresher()`, `refreshAllowedIPs()`
- `README.md` - Added network isolation section with all three modes
- `.github/workflows/ci.yml` - Increased storage pool from 5GiB to 15GiB
- `tests/meta/installation_smoke_test.py` - Added retry logic for transient network issues

## 0.3.2 (2026-01-14)

Add network isolation to prevent containers from accessing local/internal networks while allowing full internet access for development workflows.

### Features
- [Feature] Network isolation - Block container access to private networks (RFC1918) and cloud metadata endpoints by default
- [Feature] `--network` flag to control network mode: `restricted` (default) or `open`
- [Feature] Dynamic gateway discovery in tests to work on any network configuration
- [Feature] Comprehensive network isolation test suite (6 tests covering restricted/open modes)

### Bug Fixes
- [Fix] Dummy image build - Fix `buildCustom()` to push dummy file to container, enabling test image builds
- [Fix] Incus ACL configuration - Add explicit `egress action=allow` rule to prevent default deny behavior

### Enhancements
- [Enhancement] Network documentation - Add comprehensive `NETWORK.md` with security model, configuration, and testing guide
- [Enhancement] Two-step ACL application - Use `device override` followed by `device set` for proper ACL attachment
- [Enhancement] Integration tests use backgrounded containers for consistency and reliability
- [Enhancement] README updated with network isolation section and security information

### Technical Details
Network isolation implementation:
- **Restricted mode (default)**: Blocks RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and cloud metadata (169.254.0.0/16), allows all public internet
- **Open mode**: No restrictions (previous behavior)
- **Implementation**: Incus network ACLs applied at container network interface level
- **Tests**: 6 integration tests validate blocking private networks, metadata endpoints, and local gateway while allowing internet access

## 0.3.1 (2026-01-13)

Re-release of 0.3.0 with proper GitHub release automation.

## 0.3.0 (2026-01-13)

Add machine-readable output formats to enable programmatic integration with claude_yard Ruby project.

### Features
- [Feature] Add `--format=json` flag to `coi list` command for machine-readable output
- [Feature] Add `--format=raw` flag to `coi container exec --capture` for raw stdout output (exit code via $?)

### Bug Fixes
- [Fix] Power management permissions - Add wrapper scripts for shutdown/poweroff/reboot commands to work without sudo prefix (uses passwordless sudo internally)

### Enhancements
- [Enhancement] Enable programmatic integration between coi and claude_yard projects
- [Enhancement] Add 5 integration tests for new output formats (3 for list, 2 for exec)
- [Enhancement] Add integration test for power management commands without sudo
- [Enhancement] Update README with --format flag documentation and examples
- [Enhancement] Normalize all "fake-claude" references to "dummy" throughout codebase (tests, docs, scripts)
- [Enhancement] Remove FAQ.md - content no longer relevant after refactoring

## 0.2.0 (2026-01-03)

Major internal refactoring to make coi CLI-agnostic (zero breaking changes). Enables future support for tools beyond Claude Code (e.g., Aider, Cursor). Includes bug fixes for persistent containers, slot allocation, and CI improvements.

### Features
- [Feature] Add `shutdown` command for graceful container shutdown (separate from `kill`)
- [Feature] Add `attach` command to attach to running sessions
- [Feature] Add `images` command to list available Incus images
- [Feature] Add `version` command for displaying version information
- [Feature] Add GitHub Actions workflow for automated releases with pre-built binaries
- [Feature] Add automatic `~/.claude` config mounting (enabled by default)
- [Feature] Add CHANGELOG.md for version history tracking
- [Feature] Add one-shot installer script (`install.sh`)

### Refactoring (Internal API - Non-Breaking)
- [Refactor] Rename functions: `runClaude()` → `runCLI()`, `runClaudeInTmux()` → `runCLIInTmux()`, `GetClaudeSessionID()` → `GetCLISessionID()`, `setupClaudeConfig()` → `setupCLIConfig()`
- [Refactor] Rename variables: `claudeBinary` → `cliBinary`, `claudeCmd` → `cliCmd`, `claudeDir` → `stateDir`, `claudePath` → `statePath`, `claudeJsonPath` → `stateConfigPath`
- [Refactor] Rename struct fields: `ClaudeConfigPath` → `CLIConfigPath`
- [Refactor] Rename test infrastructure: "fake-claude" → "dummy", `COI_USE_TEST_CLAUDE` → `COI_USE_DUMMY`
- [Refactor] Update all internal documentation to use generic "CLI tool" terminology

### Bug Fixes
- [Fix] Persistent container filesystem persistence - Files now survive container stop/start
- [Fix] Resume flag inheritance - `--resume` properly inherits persistent/privileged flags from session metadata
- [Fix] Slot allocator race condition - Improved slot allocation logic to prevent conflicts
- [Fix] Environment variable passing in `run` command - Variables now properly passed to containers
- [Fix] Attach command container detection - Improved reliability of attach operations
- [Fix] CI networking issues - Better timeout handling (180s) and diagnostics for slower environments
- [Fix] Test suite stability - Various fixes to make tests more reliable and deterministic
- [Fix] Persistent container indicator in `coi list` - Shows "(persistent)" label correctly
- [Fix] CI cache key updated to use `testdata/dummy/**` pattern
- [Fix] Documentation inconsistencies between README and actual implementation
- [Fix] **Tmux server persistence in CI** - Explicitly start tmux server before session operations; ensures sessions work in CI and new containers
- [Fix] **Test isolation for parallel execution** - Fixed auto_attach_single_session test to use --slot flag, preventing conflicts when other sessions are running

### Enhancements
- [Enhancement] Update image builder to use `dummy` instead of `test-claude`
- [Enhancement] Improve CI networking with HTTP/HTTPS fallback tests
- [Enhancement] Add backwards-compatible test fixtures (`fake_claude_path` → `dummy_path`)
- [Enhancement] Update dummy script with generic terminology and documentation
- [Enhancement] Improve README with complete command documentation (attach, images, version, shutdown)
- [Enhancement] Update configuration examples with `mount_claude_config` option
- [Enhancement] Document `--storage` flag in README
- [Enhancement] Add refactoring documentation (CLAUDE_REFERENCES_ANALYSIS.md, REFACTORING_SUMMARY.md, REFACTORING_PHASE2.md)
- [Enhancement] Add "See Also" section in README with links to documentation
- [Enhancement] **Tmux architecture** - Sessions created detached then attached separately; tmux server explicitly started before operations for reliability
- [Enhancement] **Python linting with ruff** - Added ruff linter (Python equivalent of rubocop) to CI, auto-fixed 68 issues, formatted 166 test files for consistency
- [Enhancement] **CI tests now run all attach tests** - Removed skipif decorators after fixing tmux persistence, all tests pass in CI

### Changes
- [Change] Rename images from `claudeyard-*` to `coi-*` for consistency
- [Change] **Session creation pattern** - Changed from `tmux new-session` (single command) to `tmux new-session -d` + `tmux attach` (two-step pattern) for better detach/reattach support

## 0.1.0 (2025-12-11)

Initial release of claude-on-incus (coi) - Run Claude Code in isolated Incus containers.

### Core Features

- [Feature] Multi-slot support for running parallel Claude sessions on same workspace
- [Feature] Session persistence with `.claude` directory restoration
- [Feature] Persistent container mode to keep containers alive between sessions
- [Feature] Workspace isolation with automatic mounting
- [Feature] TOML-based configuration system with profile support
- [Feature] Automatic UID mapping for correct file permissions (no permission hell)
- [Feature] Environment variable passing to containers
- [Feature] Persistent storage mounting across sessions

### CLI Commands

- [Feature] `shell` command - Interactive Claude sessions with full resume support
- [Feature] `run` command - Execute commands in ephemeral containers
- [Feature] `build` command - Build sandbox and privileged Incus images
- [Feature] `list` command - List active containers and saved sessions
- [Feature] `info` command - Show detailed session information
- [Feature] `clean` command - Clean up stopped containers and old sessions
- [Feature] `tmux` command - Tmux integration for background processes

### Container Images

- [Feature] Sandbox image (`coi-sandbox`) - Ubuntu 22.04 + Docker + Node.js + Claude CLI + tmux
- [Feature] Privileged image (`coi-privileged`) - Sandbox + GitHub CLI + SSH + Git config
- [Feature] Automatic container lifecycle management (ephemeral vs persistent)

### Configuration

- [Feature] Configuration hierarchy: built-in defaults → system → user → project → env vars → CLI flags
- [Feature] Named profiles with environment override support
- [Feature] Project-specific configuration (`.claude-on-incus.toml`)
- [Feature] User configuration (`~/.config/claude-on-incus/config.toml`)

### Session Management

- [Feature] Automatic session saving on exit
- [Feature] Resume from previous sessions with `--resume` flag
- [Feature] Session auto-detection (resume latest session for workspace)
- [Feature] Graceful Ctrl+C handling with cleanup
- [Feature] Session metadata tracking (workspace, slot, timestamp, flags)

### Testing

- [Feature] Comprehensive integration test suite (3,900+ lines)
- [Feature] CLI command tests for all commands
- [Feature] Feature scenario tests for workflows
- [Feature] Error handling tests for edge cases

### Documentation

- [Feature] Comprehensive README with Quick Start guide
- [Feature] Why Incus vs Docker comparison section
- [Feature] Architecture diagrams and explanations
- [Feature] Configuration examples and hierarchy documentation
- [Feature] Persistent mode guide (`PERSISTENT_MODE.md`)
- [Feature] Integration testing documentation (`INTE.md`)
