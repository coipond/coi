package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/tool"
)

// SeedToolConfigForRun seeds the AI tool's CLI config/credentials, model/effort
// container env, and sandbox context into an already-launched container, for the
// headless `coi run --prompt` path (#701). The lean `coi run` pipeline does not
// call session.Setup, so it otherwise lacks the tool auth + context that a
// headless agent needs — this mirrors the fresh-session steps 10.5–13 of Setup
// (auto-context path → setupCLIConfig → applyToolContainerEnv → sandbox context →
// auto-context file) so a prompt run authenticates and loads context exactly like
// an interactive `coi shell` session.
//
// It targets a FRESH session only (no resume): each prompt fire is a new
// ephemeral session by design, so there is no restored config to preserve.
// result must have Manager, ContainerName, ContainerWorkspacePath, and HomeDir
// populated. Individual seeding failures are logged and tolerated (matching
// Setup) rather than aborting the run; a hard error is returned only for an
// unreadable CLIConfigPath stat.
func SeedToolConfigForRun(ctx context.Context, result *SetupResult, opts SetupOptions) error {
	if opts.Logger == nil {
		opts.Logger = func(string) {}
	}
	if opts.Tool == nil {
		return nil
	}

	// 10.5 Auto-context path (must precede setupCLIConfig so it lands in the
	// tool's GetSandboxSettings output).
	if config.BoolVal(opts.Context.Auto) {
		if acp, ok := opts.Tool.(tool.ToolWithAutoContextPath); ok {
			acp.SetAutoContextPath(filepath.Join(result.HomeDir, "SANDBOX_CONTEXT.md"))
		}
	}

	// 11. Tool CLI config + credentials + sandbox settings.
	if tcf, ok := opts.Tool.(tool.ToolWithConfigDirFiles); ok {
		if opts.CLIConfigPath != "" {
			_, statErr := os.Stat(opts.CLIConfigPath)
			hostDirExists := statErr == nil
			if hostDirExists || tcf.AlwaysSetupConfig() {
				opts.Logger(fmt.Sprintf("Setting up %s config...", opts.Tool.Name()))
				if err := setupCLIConfig(result.Manager, opts.CLIConfigPath, result.HomeDir, tcf, opts.Logger); err != nil {
					opts.Logger(fmt.Sprintf("Warning: Failed to setup %s config: %v", opts.Tool.Name(), err))
				}
			} else if statErr != nil && !os.IsNotExist(statErr) {
				return fmt.Errorf("failed to check %s config directory: %w", opts.Tool.Name(), statErr)
			}
		} else if tcf.AlwaysSetupConfig() {
			if err := setupCLIConfig(result.Manager, opts.CLIConfigPath, result.HomeDir, tcf, opts.Logger); err != nil {
				opts.Logger(fmt.Sprintf("Warning: Failed to setup %s config: %v", opts.Tool.Name(), err))
			}
		}
	} else if opts.Tool.ConfigDirName() == "" {
		opts.Logger(fmt.Sprintf("Tool %s uses ENV-based auth, skipping config setup", opts.Tool.Name()))
	}

	// 11.1 Persist the tool's resolved model/effort as container-level env so the
	// launch exec inherits it.
	applyToolContainerEnv(ctx, result.ContainerName, result.ContainerWorkspacePath, opts.Tool, opts.Logger)

	// 12. Sandbox context (~/SANDBOX_CONTEXT.md + optional .json).
	contextContent := injectSandboxContext(result, opts)

	// 13. Auto-context file (tool's native auto-load file, e.g. ~/.claude/CLAUDE.md).
	if config.BoolVal(opts.Context.Auto) && contextContent != "" {
		if acf, ok := opts.Tool.(tool.ToolWithAutoContextFile); ok {
			if err := injectAutoContextFile(result.Manager, acf, contextContent, result.HomeDir, opts.Logger); err != nil {
				opts.Logger(fmt.Sprintf("Warning: Failed to inject auto-context file: %v", err))
			}
		}
	}

	return nil
}
