<p align="center">
  <img src="misc/logo.png" alt="Coi (Code on Incus) logo" width="350">
</p>

# Coi (Code on Incus)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mensfeld/coi)](https://golang.org/)
[![Latest Release](https://img.shields.io/github/v/release/mensfeld/coi)](https://github.com/mensfeld/coi/releases)
[![Join the chat at https://slack.karafka.io](https://raw.githubusercontent.com/karafka/misc/master/slack.svg)](https://slack.karafka.io)

**Give the agent a machine. Just not yours.**

`coi` runs your AI coding tool (Claude Code, Codex, opencode, pi, omp) inside its own isolated Linux system - a full-OS container with root access, systemd, Docker, and the freedom to install anything. The agent works like it would on a real server - but it can't touch your host, can't see your credentials, and if it does something dangerous, `coi` pauses or kills the container on its own.

One command drops you into a coding session. Your project is mounted, file permissions just work, and your SSH keys, tokens, and environment variables never enter the container unless you explicitly say so.

Built by developers, for developers who run AI agents and want to know what those agents are doing. Not a product, not a startup - a tool that does the job.

<p align="center">
  <a href="https://www.youtube.com/watch?v=t78-JUnTK5Q">
    <img src="https://img.youtube.com/vi/t78-JUnTK5Q/maxresdefault.jpg" alt="BetterStack video about Coi" width="600">
  </a>
  <br>
  <em>Watch the BetterStack video about Coi</em>
</p>

![Demo](misc/demo.gif)

## Get started in three commands

```bash
# 1. Install
curl -fsSL https://raw.githubusercontent.com/mensfeld/coi/master/install.sh | bash

# 2. Build the base image (first time only, ~5-10 min)
coi build

# 3. Start coding - from any project directory
cd your-project
coi shell
```

That's it. Your agent is now running in an isolated container with your project at `/workspace`, correct file ownership (no more `chown`), Docker and `gh` available inside, every workspace change saved back to the host - and **no** access to your host SSH keys, env vars, or credentials.

> Requires Linux with [Incus](https://linuxcontainers.org/incus/docs/main/installing/) (macOS works too, via Colima/Lima - see [macOS Setup](https://github.com/mensfeld/coi/wiki/macOS-Setup-Guide)).

## Who it's for

- You run AI coding agents and want them to have **full machine access** - root, Docker, package managers, services - without risking your host.
- You want to **know when an agent does something suspicious**, not find out after the fact.
- You run **multiple agents in parallel** and need them isolated from each other.
- You want **persistent dev environments** that survive restarts, not throwaway containers that lose your setup every time.
- You care about your **credentials never ending up** inside an agent-controlled environment.

## Features

- **A real machine, not a locked box** - Incus *system* containers give the agent a full OS: root, systemd, native Docker, package managers, services.
- **Correct file ownership** - workspace edits land on the host owned by you, no `chown` dance.
- **Your credentials stay home** - SSH keys, tokens, `.env`, and host env vars never enter the container unless you explicitly mount or forward them.
- **Active defense** - kernel-level monitoring catches reverse shells, C2, exfil, and DNS tunneling in real time, and **auto-pauses on HIGH / auto-kills on CRITICAL**.
- **Network isolation** - nftables egress control in three modes (open / restricted / allowlist), DNS pinning, and per-host port scoping.
- **Parallel agents, fully isolated** - multiple slots per project, each with its own home; nothing leaks between them.
- **Persistent or ephemeral** - keep a box with its installed packages, or throw it away on exit; workspace files and session history are always saved, and any session resumes with full history.
- **Profiles** - reusable named setups (image, tool, limits, network, build scripts, agent instructions) applied with a single flag, with inheritance.
- **Supply-chain guards** - git hooks and IDE configs mounted read-only, protected paths, and a branch guard that blocks direct commits/pushes to `main`.
- **Headless + auditable** - run prompts to completion for cron/CI (exit codes propagate), stream a JSONL threat log to your SIEM, and diagnose the whole setup with `coi health`.

## Profiles: your setups, one flag

Profiles are the feature you'll reach for every day. A profile is a **reusable, named container setup** - image, tool, resource limits, mounts, network mode, build scripts, and AI-agent instructions bundled into one template you can apply with a single flag.

```bash
coi shell --profile rust-dev        # spin up your Rust environment, ready to go
coi profile create rust-dev         # scaffold a new profile, then edit its config.toml
coi profile list                    # see what you've got
```

A profile is just a `config.toml`:

```toml
# ~/.coi/profiles/rust-dev/config.toml
inherits = "hardened"        # optional: build on another profile

[container]
image = "coi-default"
persistent = true            # keep the box (and its installed packages) between sessions

[tool]
name = "claude"

[limits]
cpu = "4"
memory = "8GiB"

[network]
mode = "restricted"          # open / restricted / allowlist
```

Profiles support **inheritance**, ship AI-agent context files, and can carry their own build scripts - so "my hardened Python box with these limits and these tools" becomes one word. A built-in **`hardened`** preset locks a session down for untrusted code. See the [Profiles wiki page](https://github.com/mensfeld/coi/wiki/Profiles) for the full reference, the `hardened` preset, and the schema.

## Supported AI tools

**Claude Code** (default) · **Codex CLI** · **opencode** · **pi** · **omp** (Oh My Pi) - pick one in config or a profile:

```toml
# ~/.coi/config.toml or ./.coi/config.toml
[tool]
name = "claude"              # or "codex", "opencode", "pi", "omp"
permission_mode = "bypass"   # run autonomously ("bypass") or ask first ("interactive")
```

_Aider and Cursor are on the way._ See the [Supported Tools wiki page](https://github.com/mensfeld/coi/wiki/Supported-Tools) for per-tool auth, and [Container Lifecycle & Sessions](https://github.com/mensfeld/coi/wiki/Container-Lifecycle-and-Sessions#running-a-different-ai-tool-in-the-same-container-v012) for running two tools in the same persistent container.

## Everyday commands

```bash
coi shell                 # interactive AI session (Claude Code by default)
coi run -- npm test       # run any command in the sandbox (streams output, propagates exit code)
coi run --prompt-name nightly   # fire-and-forget: run the agent headlessly from a predefined prompt
coi top                   # per-container CPU/memory/IO, resolved to workspace + alias
coi monitor               # real-time security dashboard
coi list --all            # active containers + saved sessions
coi attach                # attach to a running session
coi audit                 # stream the JSONL threat-event log (pipe into a SIEM or jq)
coi shutdown / coi kill   # stop or force-kill containers
coi clean                 # remove stopped containers and orphaned resources
```

Drop a `.coi/config.toml` in any repo to auto-configure `coi` for that project - teams share one image, network mode, and limits. Run `coi <command> --help` for any command. To run agents unattended (headless prompts + cron), see [Headless Orchestration](https://github.com/mensfeld/coi/wiki/Headless-Orchestration).

## Documentation

The README is the pitch; the wiki is the manual. Everything lives there in full:

- **[Configuration](https://github.com/mensfeld/coi/wiki/Configuration)** - the complete config reference, precedence, and per-repo setup
- **[Profiles](https://github.com/mensfeld/coi/wiki/Profiles)** - reusable setups, the `hardened` preset, inheritance, and the JSON schema
- **[Supported Tools](https://github.com/mensfeld/coi/wiki/Supported-Tools)** - per-tool auth and configuration
- **[Headless Orchestration](https://github.com/mensfeld/coi/wiki/Headless-Orchestration)** - `coi run --prompt`, predefined prompts, and cron
- **[Network Isolation](https://github.com/mensfeld/coi/wiki/Network-Isolation)** - restricted/allowlist/open modes, DNS pinning, egress and per-host port controls
- **[Security Monitoring](https://github.com/mensfeld/coi/wiki/Security-Monitoring)** & **[Audit Log](https://github.com/mensfeld/coi/wiki/Audit-Log)** - threat detection, automated response, and the event format
- **[Security Best Practices](https://github.com/mensfeld/coi/wiki/Security-Best-Practices)** - protected paths, the trust model, hardening
- **[Container Lifecycle & Sessions](https://github.com/mensfeld/coi/wiki/Container-Lifecycle-and-Sessions)** - ephemeral vs. persistent, resume, aliases, running multiple tools in one box
- **[Resource & Time Limits](https://github.com/mensfeld/coi/wiki/Resource-and-Time-Limits)** · **[Snapshot Management](https://github.com/mensfeld/coi/wiki/Snapshot-Management)** · **[Image Management](https://github.com/mensfeld/coi/wiki/Image-Management)**
- **[File Transfer](https://github.com/mensfeld/coi/wiki/File-Transfer)** · **[Tmux Automation](https://github.com/mensfeld/coi/wiki/Tmux-Automation)** · **[Container Operations](https://github.com/mensfeld/coi/wiki/Container-Operations)**
- **[System Health Check](https://github.com/mensfeld/coi/wiki/System-Health-Check)** - `coi health` diagnoses your setup end-to-end
- **[Troubleshooting](https://github.com/mensfeld/coi/wiki/Troubleshooting)** · **[FAQ](https://github.com/mensfeld/coi/wiki/FAQ)** · **[Migration Guide](https://github.com/mensfeld/coi/wiki/Migration-Guide)**

## Why Incus, not Docker?

Incus (a modern LXD fork) gives you **system containers** - which behave like lightweight VMs (a real init system and full OS userspace) while sharing the host kernel, so they start in seconds - instead of Docker's application containers. That means one clean isolation layer running a full OS with native Docker inside, correct file ownership on the host by default, and no Docker Desktop, no vendor lock-in, no opaque VM nesting. It's Linux-native and fully open source. (More in the [FAQ](https://github.com/mensfeld/coi/wiki/FAQ).)

## Coi vs. the alternatives

| Capability | **Coi** | Docker Sandbox | Bare Metal |
|------------|---------|----------------|------------|
| Credential isolation | Default (never exposed) | Partial | None |
| Real-time threat detection | Kernel-level (nftables) | No | No |
| Reverse-shell / exfil response | Auto-kill / auto-pause | No | No |
| Network isolation | nftables (3 modes) | Basic | No |
| Supply-chain protection | Git hooks / IDE configs read-only | No | No |
| Audit logging | JSONL forensics | No | No |
| Runs on Linux natively | Yes | microVM only on macOS/Windows | - |

## Getting help

- **Slack**: [Join the Coi community](https://slack.karafka.io) - ask questions, report issues, share feedback
- **GitHub Issues**: [Open an issue](https://github.com/mensfeld/coi/issues) for bugs and feature requests
- **Wiki**: [Browse the documentation](https://github.com/mensfeld/coi/wiki)
