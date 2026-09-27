package cli

import (
	"fmt"
	"os"
	"regexp"

	"github.com/mensfeld/code-on-incus/internal/config"
	"github.com/mensfeld/code-on-incus/internal/container"
	"github.com/mensfeld/code-on-incus/internal/network"
	"github.com/mensfeld/code-on-incus/internal/timing"
	"github.com/spf13/cobra"
)

// Version is the current version of coi (injected via ldflags at build time)
var Version = "dev"

// InstallSource records how this binary was installed (injected via ldflags at
// build time). Packaging sets it to the package format that owns the binary —
// "deb", "rpm", "arch", ... — while plain source builds leave it "source". Any
// non-"source" value disables the self-updater; see installedFromPackage and
// packageUpdateCommands in update.go.
var InstallSource = "source"

// rootVersionTemplate is the text/template cobra renders for `coi --version`.
// It mirrors the first line the `coi version` subcommand prints so both surfaces
// agree; {{.Version}} is rootCmd.Version, which is normalizeVersion(Version).
const rootVersionTemplate = "code-on-incus (coi) v{{.Version}}\n"

// App holds the shared CLI state that is populated from persistent flags and
// config loading in PersistentPreRunE. Grouping this in a struct rather than
// package-level vars makes it easier to construct an isolated instance in
// tests and clears the path toward a multi-session daemon model.
type App struct {
	workspace       string
	slot            int
	persistent      bool // config-driven: [container] persistent (no CLI flag)
	resume          string
	continueSession string
	profile         string
	cfg             *config.Config
}

// sessionName returns the resolved [container] session_name — the identity-key
// override for every workspace→container derivation (empty = key by path).
func (a *App) sessionName() string {
	if a.cfg == nil {
		return ""
	}
	return a.cfg.Container.SessionName
}

// hardeningPolicy builds the container-level kernel-surface policy from
// [container] docker and [security] reduce_kernel_surface. It passes the raw
// flags; the precedence ("reduce_kernel_surface wins") is resolved in exactly
// one place, HardeningPolicy.DockerEnabled.
func (a *App) hardeningPolicy() container.HardeningPolicy {
	if a.cfg == nil {
		return container.DefaultHardeningPolicy()
	}
	return container.HardeningPolicy{
		Docker:                    a.cfg.Container.IsDockerEnabled(),
		ReduceKernelSurface:       a.cfg.Security.IsReduceKernelSurfaceEnabled(),
		ReduceKernelSurfaceStrict: a.cfg.Security.IsReduceKernelSurfaceStrictEnabled(),
	}
}

// warnDockerHardeningConflict surfaces an explicit `[container] docker = true`
// being overridden by kernel-surface hardening (security wins; nesting is part
// of the surface being reduced). The message names whichever flag the user
// actually set — reduce_kernel_surface_strict implies the base tier, so when
// only the strict flag is on, pointing at reduce_kernel_surface would name a
// setting absent from their config.
func warnDockerHardeningConflict(cfg *config.Config) {
	if cfg == nil || !cfg.Security.IsReduceKernelSurfaceEnabled() {
		return
	}
	if cfg.Container.Docker != nil && *cfg.Container.Docker {
		flag := "reduce_kernel_surface"
		if !cfg.Security.IsReduceKernelSurfaceBaseEnabled() {
			flag = "reduce_kernel_surface_strict"
		}
		fmt.Fprintf(os.Stderr,
			"Warning: [security] %s = true disables Docker support; ignoring [container] docker = true\n", flag)
	}
}

// applyDefaultProfileForOps applies the [defaults] profile fallback for
// OPERATIONAL commands (attach, monitor, snapshot) so a profile-carried
// session_name — the documented placement — resolves the same container
// identity the launch used. Unlike the session commands' fallback this is
// error-TOLERANT: per #607, operational commands must keep working on a
// misconfigured default profile (they are the recovery tools), so an unknown
// profile is ignored rather than fatal. The same suppression rules apply: an
// explicit --profile (or alias/resume-applied profile) means the fallback
// never applies, exactly as at launch. A session launched with a
// session_name-carrying profile selected by --profile or an alias needs the
// same flag repeated on the operational command.
func (a *App) applyDefaultProfileForOps(cmd *cobra.Command) {
	if _, err := a.applyDefaultProfileFallback(cmd); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v (continuing without the default profile)\n", err)
	}
}

// app is the singleton used by the cobra command tree. Execute() resets it to
// a zero value on each call so tests that invoke Execute() multiple times
// start with clean state (cobra re-parses flags, PersistentPreRunE reloads
// the config).
var app = &App{}

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "coi",
	Short: "Code on Incus - Run AI coding tools in isolated Incus containers",
	Long: `code-on-incus (coi) is a CLI tool for running AI coding assistants in Incus containers
with session persistence, workspace isolation, and multi-slot support.

By default runs Claude Code. Other tools can be configured via the tool.name config option.

Examples:
  coi                          # Start interactive AI coding session (same as 'coi shell')
  coi shell --slot 2           # Use specific slot
  coi run -- npm test          # Run a command in the sandbox
  coi run                      # Run the workspace run script (coi-run)
  coi build                    # Build coi image
  coi image list               # List available images
  coi list                     # List active sessions
`,
	Version: normalizeVersion(Version),
	// When called without subcommand, run shell command
	RunE: func(cmd *cobra.Command, args []string) error {
		// Execute shell command with the same args
		return shellCmd.RunE(cmd, args)
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load config
		var err error
		app.cfg, err = config.Load()
		if err != nil {
			// Allow health command to run with defaults even if config is broken
			if cmd.Name() == "health" {
				app.cfg = config.GetDefaultConfig()
			} else {
				return fmt.Errorf("failed to load config: %w", err)
			}
		}

		// Apply profile if specified
		if app.profile != "" {
			if err := app.cfg.ApplyProfile(app.profile); err != nil {
				return err
			}
		}

		// A misconfigured [defaults] profile is caught at the point it is
		// applied (applyDefaultProfileFallback, only for coi shell/run), not
		// here: this hook runs for EVERY command, so validating here would break
		// unrelated operational commands (coi list/kill/clean/attach/…) on a
		// typo — including the very commands used to recover — even though they
		// never apply a profile (#607 follow-up).

		// Apply Incus configuration from config file
		container.Configure(app.cfg.Incus.Project, app.cfg.Incus.CodeUser, app.cfg.Incus.CodeUID)

		// Honor [network] use_sudo process-wide so every network sudo entry point
		// (nft probe, iptables fallback, boot block, health/build/clean) behaves
		// as if passwordless sudo were unavailable when disabled.
		network.SetSudoAllowed(app.cfg.Network.SudoAllowed())

		// Persistence is config-driven ([container] persistent, settable per
		// profile) — the former --persistent flag was removed.
		app.persistent = config.BoolVal(app.cfg.Container.Persistent)

		// Silence usage output for RunE errors. Setting this here (in
		// PersistentPreRunE) rather than globally means cobra still prints
		// usage for arg/flag validation errors (which fire before this hook),
		// but won't dump usage for RunE errors like ExitCodeError.
		cmd.SilenceUsage = true

		return nil
	},
}

// applyDefaultProfileFallback applies [defaults] profile as the lowest-priority
// source of a profile (#607): it takes effect only when the user selected no
// profile by any other means — no --profile flag, no alias-saved profile, and
// no resume-remembered profile. a.profile being empty is the signal that
// nothing else claimed it (the explicit/alias/resume paths all set it when they
// apply), so this applies at most once and can never stack on top of another
// profile.
//
// This is the single guard for a misconfigured [defaults] profile: it runs only
// for the commands that consume the default profile (coi shell/run), before any
// container work, so a typo fails those sessions fast without breaking unrelated
// commands. A name that resolves to no known profile is reported with an
// actionable message rather than ApplyProfile's terser wording.
//
// It returns whether it applied a profile so the caller can recompute
// a.persistent for its own context — the profile may set [container] persistent,
// but the caller decides how that reconciles with session-resume metadata, which
// this helper cannot see.
func (a *App) applyDefaultProfileFallback(cmd *cobra.Command) (bool, error) {
	if a.profile != "" || cmd.Flags().Changed("profile") {
		return false, nil
	}
	name := a.cfg.Defaults.Profile
	if name == "" {
		return false, nil
	}
	if a.cfg.GetProfile(name) == nil {
		return false, fmt.Errorf(
			"[defaults] profile = %q does not name a known profile; "+
				"run 'coi profile list' to see available profiles", name)
	}
	if err := a.cfg.ApplyProfile(name); err != nil {
		return false, err
	}
	a.profile = name
	// The profile may change [incus] identity; mirror the reconfigure the
	// explicit --profile and alias/resume paths do.
	container.Configure(a.cfg.Incus.Project, a.cfg.Incus.CodeUser, a.cfg.Incus.CodeUID)
	return true, nil
}

// removedFlagConfig maps each removed, config-shaped CLI flag to the config
// setting that replaces it. Everything config-shaped goes via config/profiles;
// flags are only for per-invocation choices.
var removedFlagConfig = map[string]string{
	"--image":       `[container] image = "..."`,
	"--persistent":  `[container] persistent = true`,
	"--tmux":        `[shell] use_tmux = false`,
	"--tool":        `[tool] name = "opencode"`,
	"--compression": `[container.build] compression = "none"`,
	"--timeout":     `[container] shutdown_timeout = 30`,
}

// removedFlagRe matches the removed flags as EXACT tokens inside a
// flag-error message ("unknown flag: --image", "flag needs an argument:
// --image"). The boundary check prevents false hints for flags that merely
// share the prefix (--images, --image-tag, --persistent-home): the token must
// be followed by end-of-string, whitespace, or '=' — never by more flag-name
// characters. Commands that legitimately keep one of these names (e.g.
// `coi image publish --compression`) never reach this path because their
// flag exists and parses.
var removedFlagRe = regexp.MustCompile(`(--image|--persistent|--tmux|--tool|--compression|--timeout)($|[\s=])`)

// removedFlagHint upgrades the bare "unknown flag" error for a removed,
// config-shaped flag into an actionable migration message pointing at the
// replacement config setting (settable globally, per project, or per profile).
func removedFlagHint(cmd *cobra.Command, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if m := removedFlagRe.FindStringSubmatch(msg); m != nil {
		return fmt.Errorf("%s\n\nThe %s flag was removed — config-shaped settings live in config, not flags.\n"+
			"Set it in ~/.coi/config.toml, ./.coi/config.toml, or a profile (--profile <name>):\n"+
			"  %s",
			msg, m[1], removedFlagConfig[m[1]])
	}
	return err
}

// Execute runs the root command
func Execute() error {
	// Reset app state so that repeated calls (e.g. in tests) start clean.
	// Cobra re-parses flags on every Execute, so flag-bound fields are
	// repopulated correctly from the fresh zero value.
	*app = App{}

	// Deferred here rather than inside a command so the report covers the whole
	// invocation, teardowns included (a run pipeline tears down in its own
	// defers, which fire before this one). No-op unless COI_TIMING_DEBUG is set.
	defer timing.Report(os.Stderr)

	return rootCmd.Execute()
}

func init() {
	// Keep `coi --version` (cobra's version flag) consistent with the `coi
	// version` subcommand: same "code-on-incus (coi) v<semver>" line, and the
	// version already normalized (rootCmd.Version above) so a stray/doubled 'v'
	// from a mis-tagged build can't leak here either.
	rootCmd.SetVersionTemplate(rootVersionTemplate)

	// Global flags available to all commands.
	// NOTE: --image and --persistent were removed on purpose — anything
	// config-shaped goes via config/profiles ([container] image / persistent).
	// removedFlagHint below turns their unknown-flag errors into a migration hint.
	rootCmd.PersistentFlags().StringVarP(&app.workspace, "workspace", "w", ".", "Workspace directory to mount")
	rootCmd.PersistentFlags().IntVar(&app.slot, "slot", 0, "Slot number for parallel sessions (0 = auto-allocate)")
	rootCmd.PersistentFlags().StringVar(&app.resume, "resume", "", "Resume from session ID (omit value to auto-detect)")
	rootCmd.PersistentFlags().Lookup("resume").NoOptDefVal = "auto"
	rootCmd.PersistentFlags().StringVar(&app.continueSession, "continue", "", "Alias for --resume")
	rootCmd.PersistentFlags().Lookup("continue").NoOptDefVal = "auto"
	rootCmd.PersistentFlags().StringVar(&app.profile, "profile", "", "Use named profile")

	rootCmd.SetFlagErrorFunc(removedFlagHint)

	// Prevent cobra from double-printing errors — main.go handles error output.
	rootCmd.SilenceErrors = true

	// Add subcommands
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(shellCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(imageCmd)     // coi image <subcommand>
	rootCmd.AddCommand(containerCmd) // New: coi container <subcommand>
	rootCmd.AddCommand(fileCmd)      // New: coi file <subcommand>
	rootCmd.AddCommand(cleanCmd)
	rootCmd.AddCommand(killCmd)
	rootCmd.AddCommand(hostsCmd) // coi hosts <add|list|remove> (#605)
	rootCmd.AddCommand(persistCmd)
	rootCmd.AddCommand(tmuxCmd)
	rootCmd.AddCommand(toolCmd) // coi tool <spec> (#751)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(snapshotCmd)
	rootCmd.AddCommand(unfreezeCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(profileCmd)
	rootCmd.AddCommand(schemaCmd)
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(untrustCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(attachCmd)
	rootCmd.AddCommand(shutdownCmd)
	rootCmd.AddCommand(monitorCmd)
	rootCmd.AddCommand(topCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")
		applyJSONFormatAlias(cmd, &format)
		if format != "text" && format != "json" {
			return &ExitCodeError{Code: 2, Message: fmt.Sprintf("invalid format %q: must be 'text' or 'json'", format)}
		}
		if format == "json" {
			fmt.Printf(`{"version":%q,"url":"https://github.com/mensfeld/code-on-incus"}`+"\n", "v"+normalizeVersion(Version))
			return nil
		}
		fmt.Printf("code-on-incus (coi) v%s\n", normalizeVersion(Version))
		fmt.Println("https://github.com/mensfeld/code-on-incus")
		return nil
	},
}

func init() {
	versionCmd.Flags().String("format", "text", "Output format: text or json")
	versionCmd.Flags().Bool("json", false, "Alias for --format json")
}
