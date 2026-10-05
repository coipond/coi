package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/coipond/coi/internal/alias"
	"github.com/coipond/coi/internal/session"
	"github.com/spf13/cobra"
)

// confirmYN prints prompt and reads a line from stdin, returning true only when
// the user answers "y" or "Y". This is the shared semantics of coi's inline
// "[y/N]" confirmation prompts (destructive commands like clean/kill/persist).
func confirmYN(prompt string) bool {
	fmt.Print(prompt)
	var response string
	_, _ = fmt.Scanln(&response)
	return response == "y" || response == "Y"
}

// validateTextOrJSON returns a usage error (exit code 2) when format is neither
// "text" nor "json", using the message shared by the format-taking commands.
func validateTextOrJSON(format string) error {
	if format != "text" && format != "json" {
		return &ExitCodeError{Code: 2, Message: fmt.Sprintf("invalid format '%s': must be 'text' or 'json'", format)}
	}
	return nil
}

// resolveNameOrAlias resolves a running container's alias to its container name,
// returns the input unchanged when it is already a container name, and returns
// the resolver error when it is neither a resolvable alias nor a container name.
func resolveNameOrAlias(nameOrAlias string) (string, error) {
	if resolved, err := alias.ResolveAliasForRunning(nameOrAlias); err == nil {
		return resolved, nil
	} else if !alias.IsContainerName(nameOrAlias) {
		return "", err
	}
	return nameOrAlias, nil
}

// stderrLogFn is the shared line logger for the session helpers that take a
// func(string): it writes msg to stderr with a trailing newline.
func stderrLogFn(msg string) {
	fmt.Fprintf(os.Stderr, "%s\n", msg)
}

// applyConfigEnv overlays the three config-sourced environment layers onto env
// in increasing-priority (last-wins) order: [defaults].environment, then
// forward_env (host values, warning on an unset var), then env_commands
// (freshly minted per session, fatal on error). Shared by coi shell
// (buildContainerEnv) and coi run (appendEnvArgs) so the precedence and the
// unset-var warning can't drift between the two launch paths.
func (a *App) applyConfigEnv(env map[string]string) error {
	// Static environment from config (defaults.environment + profile environment)
	for k, v := range a.cfg.Defaults.Environment {
		env[k] = v
	}
	// Resolve forward_env from config, look up host values
	for _, name := range a.cfg.Defaults.ForwardEnv {
		if val, ok := os.LookupEnv(name); ok {
			env[name] = val
		} else {
			fmt.Fprintf(os.Stderr, "Warning: forward_env variable %q is not set on host, skipping\n", name)
		}
	}
	// Command-sourced env vars (highest precedence — freshly minted per session).
	envCommandValues, err := a.resolveEnvCommands()
	if err != nil {
		return err
	}
	for k, v := range envCommandValues {
		env[k] = v
	}
	return nil
}

// runPipelineWithSignals installs a SIGINT/SIGTERM handler that triggers
// pipeline.Teardown immediately — so cleanup runs even while a blocking incus
// exec ignores ctx cancellation — then runs the pipeline. A dedicated sigChan
// (not ctx.Done) avoids the non-determinism of both firing at once; Teardown is
// idempotent so the caller's own `defer pipeline.Teardown()` stays safe. Shared
// by coi shell and coi run.
func runPipelineWithSignals(ctx context.Context, pipeline *session.Pipeline, phases ...session.Phase) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigChan:
			fmt.Fprintf(os.Stderr, "\nReceived interrupt signal, cleaning up...\n")
			pipeline.Teardown()
		case <-done:
		}
	}()
	return pipeline.Run(ctx, phases...)
}

// applyJSONFormatAlias overrides *format to "json" when the --json alias flag is
// set on cmd. Standardizes the text|json output convention: every command that
// offers --format text|json also accepts --json as a convenience alias.
func applyJSONFormatAlias(cmd *cobra.Command, format *string) {
	if j, _ := cmd.Flags().GetBool("json"); j {
		*format = "json"
	}
}
