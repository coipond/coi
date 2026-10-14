---
name: coi-profile
description: Write, edit and validate Coi (Code on Incus) profiles, the config.toml files under ~/.coi/profiles/<name>/ or .coi/profiles/<name>/ that set a sandbox's image, AI tool, resource limits, mounts, network mode and security settings. Use when asked to create or change a coi profile or a coi config.toml.
---

# Writing Coi profiles

A Coi profile is a directory named after the profile that holds a `config.toml`, plus any files it points to (a build script, a context `.md`, prompt files). It is applied with `coi shell --profile <name>` or `coi run --profile <name>`.

Never guess a key or a value. The `coi` binary is the source of truth: read its schema, and validate every file you write.

## Workflow

1. **Read the schema first.** `coi schema profile` prints the JSON Schema (2020-12) of a profile `config.toml`. Every accepted key, type, enum and description is in it; unknown keys are errors.

   ```bash
   coi schema profile > /tmp/coi-profile.schema.json
   jq '.properties | keys' /tmp/coi-profile.schema.json                 # top-level keys
   jq '."$defs".NetworkConfig.properties.mode' /tmp/coi-profile.schema.json  # one field, with its enum
   ```

   Section names map to `$defs` (`[network]` is `NetworkConfig`, `[limits.memory]` is `MemoryLimits`, `[container.build]` is `BuildConfig`). Read a field's `description` before you set it.

2. **See what exists.** `coi profile list` shows every profile with its source; `coi profile info <name>` prints a profile fully resolved, after inheritance. Built-ins: `default` (Coi's defaults) and `hardened` (for untrusted code).

3. **Create the profile.** Prefer `coi profile create <name> [--inherits <parent>] [--user|--project]` over making the directory by hand: it picks the location (`./.coi/profiles/` when the project has a `.coi/` directory, else `~/.coi/profiles/`) and refuses to overwrite. Then edit its `config.toml`. Do not use `coi profile create default`: it scaffolds the main `~/.coi/config.toml`, not a profile.

4. **Write only what differs from the parent.** Inherit from `default` (implicit) or `hardened`, and set just the overrides.

5. **Validate after every edit.** Fix every reported path, then validate again until it passes.

   ```bash
   coi validate profile ~/.coi/profiles/<name>/config.toml
   coi validate profile ~/.coi/profiles/<name>/config.toml --format json   # {"valid": ..., "errors": [{"path", "message"}]}
   ```

   Exit code 0 means valid, 1 invalid. The `path` (e.g. `/network/mode`) is a JSON Pointer into the file; when the message is terse, look that path up in the schema. TOML syntax errors are reported with an empty path.

6. **Check the result.** `coi profile info <name>` shows the merged profile. Confirm the inherited values are what you expect.

7. **Build the image if the profile has one.** A profile with a `[container.build]` section needs `coi build --profile <name>` before first use. Leave this to the user unless asked: it needs Incus and takes minutes.

## Example

```toml
# ~/.coi/profiles/rust-dev/config.toml
inherits = "hardened"

[container]
image = "coi-rust-dev"

[container.build]
script = "build.sh"           # relative to this profile's directory

[tool]
name = "claude"

[limits.cpu]
count = "4"

[limits.memory]
limit = "8GiB"

[network]
mode = "allowlist"
allowed_domains = ["api.anthropic.com", "crates.io", "static.crates.io", "index.crates.io", "github.com"]
```

## Rules that are easy to get wrong

- **Limits are nested tables.** Use `[limits.cpu] count = "4"` and `[limits.memory] limit = "8GiB"`, never `[limits] cpu = "4"`.
- **Allowlist entries are exact.** `allowed_domains` takes hostnames, IPv4 addresses or CIDRs, optionally with `:ports`. Wildcards (`*.example.com`) are rejected when the session starts (`coi validate profile` does not catch them), and DNS is blocked in allowlist mode, so list every host the tool needs.
- **Relative paths resolve against the profile directory**: the top-level `context` key, `[container.build] script` and `[prompts]` `file`.
- **Project profiles are untrusted.** A profile under a repo's `.coi/profiles/` is loaded with its isolation-weakening settings stripped (with a warning): `env_commands`, `forward_env`, `[ssh] forward_agent = true`, `[prompts]`, `[tool]` `context_file`/`context_json_file`/`pre_launch`, and network, security, git or Docker downgrades. Host mounts outside the workspace need `coi trust`. Put such settings in a profile under `~/.coi/profiles/`, and tell the user why.
- **`hardened` turns things off on purpose** (no Docker, ephemeral, monitoring with auto-kill, a 4-hour cap). Override one of them only when the task needs it, and say which one.
- **Validation covers the file's format alone.** `coi validate profile` does not check that the `inherits` parent exists, that the `context` file or build script is there, or that `allowed_domains` has no wildcard. `coi profile list` and `coi profile info` catch a missing `inherits` parent. The other three fail only when the profile is used (`coi shell --profile <name>`), so check them yourself and tell the user they are unverified.
