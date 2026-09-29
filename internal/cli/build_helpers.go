package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/image"
)

// resolveBuildScript returns the path to the build script to use.
// If build.Script is set, it verifies the file exists.
// If build.Commands are set, it creates a temporary script.
// Script takes precedence over commands.
// Returns the path, a cleanup function, and any error.
func resolveBuildScript(build *config.BuildConfig) (string, func(), error) {
	noop := func() {}

	// Script takes precedence over commands
	if build.Script != "" {
		scriptPath := build.Script
		if _, err := os.Stat(scriptPath); err != nil {
			return "", noop, fmt.Errorf("build script not found: %s", scriptPath)
		}
		return scriptPath, noop, nil
	}

	// Generate temporary script from commands
	if len(build.Commands) > 0 {
		tmpFile, err := os.CreateTemp("", "coi-build-*.sh")
		if err != nil {
			return "", noop, fmt.Errorf("failed to create temporary build script: %w", err)
		}

		// Write shebang and commands
		content := "#!/bin/bash\nset -e\n"
		for _, cmd := range build.Commands {
			content += cmd + "\n"
		}

		if _, err := tmpFile.WriteString(content); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return "", noop, fmt.Errorf("failed to write temporary build script: %w", err)
		}
		tmpFile.Close()

		if err := os.Chmod(tmpFile.Name(), 0o755); err != nil {
			os.Remove(tmpFile.Name())
			return "", noop, fmt.Errorf("failed to make temporary build script executable: %w", err)
		}

		cleanup := func() { os.Remove(tmpFile.Name()) }
		return tmpFile.Name(), cleanup, nil
	}

	return "", noop, fmt.Errorf("no build script or commands configured")
}

// ResolveImageName returns the effective image name using: config
// container.image (globally, per project, or per profile) > CoiAlias.
func ResolveImageName(cfg *config.Config) string {
	if cfg.Container.Image != "" {
		return cfg.Container.Image
	}
	return image.CoiAlias
}

// AutoBuildIfNeeded checks if the image is missing. When stdin is an
// interactive terminal it prompts the user to build the image on the spot;
// otherwise it returns an actionable error with build instructions.
func AutoBuildIfNeeded(cfg *config.Config, imageName string) error {
	exists, err := container.ImageExists(imageName)
	if err != nil {
		return fmt.Errorf("failed to check image: %w", err)
	}
	if exists {
		return nil
	}

	if !stdinIsTerminal() {
		return imageNotFoundError(imageName)
	}

	if !promptYesNo(fmt.Sprintf("Image '%s' not found. Build it now? (~5 min) [y/N]: ", imageName)) {
		return imageNotFoundError(imageName)
	}

	return runInlineBuild(cfg, imageName)
}

// imageNotFoundError returns the standard actionable error for a missing image.
func imageNotFoundError(imageName string) error {
	if imageName == image.CoiAlias {
		return fmt.Errorf("image '%s' not found — run 'coi build' first", imageName)
	}
	return fmt.Errorf("image '%s' not found — run 'coi build --profile <profile>' first", imageName)
}

// stdinIsTerminal reports whether os.Stdin is connected to a real terminal.
func stdinIsTerminal() bool {
	return container.StdinIsTerminal()
}

// promptYesNo prints prompt and reads a single line from stdin.
// Returns true only if the user types "y" or "Y".
func promptYesNo(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "\nWarning: failed to read input: %v\n", err)
		}
		return false
	}
	answer := strings.TrimSpace(scanner.Text())
	return strings.EqualFold(answer, "y")
}

// runInlineBuild builds imageName using the same logic as `coi build`,
// driven by the already-resolved config (profile already applied).
func runInlineBuild(cfg *config.Config, imageName string) error {
	buildPool := cfg.Container.StoragePool
	if err := container.ValidateStoragePool(buildPool); err != nil {
		return err
	}

	if imageName == image.CoiAlias {
		coiBaseImage := image.BaseImage
		if cfg.Container.Build.Base != "" {
			coiBaseImage = cfg.Container.Build.Base
		}

		// Validate the agent selection (#454) and warn if the image would be built
		// without the tool the user runs — same as `coi build`. cfg is already
		// resolved (profile applied), so there is no separate profile to consult.
		if err := prepareBuildAgents(cfg.Container.Build.Agents, effectiveToolName(cfg, nil)); err != nil {
			return err
		}

		opts := image.BuildOptions{
			Force:       false,
			ImageType:   "coi",
			BaseImage:   coiBaseImage,
			AliasName:   image.CoiAlias,
			Description: "coi image (Docker + build tools + AI agents + GitHub CLI)",
			StoragePool: buildPool,
			Agents:      cfg.Container.Build.Agents,
			Logger:      stderrLogFn,
		}
		fmt.Fprintf(os.Stderr, "Building image '%s'...\n", imageName)
		result := image.NewBuilder(opts).Build()
		if result.Error != nil {
			return fmt.Errorf("build failed: %w", result.Error)
		}
		if result.Skipped {
			fmt.Fprintf(os.Stderr, "\nImage '%s' already exists — skipping build.\n", imageName)
			return nil
		}
		fmt.Fprintf(os.Stderr, "\nImage '%s' built successfully!\n", imageName)
		if dir, err := coiDataDir(); err == nil {
			image.RecordBuild(dir, imageName, coiBaseImage)
		}
		return nil
	}

	// Custom image: requires build config in the resolved cfg.
	if !cfg.Container.Build.HasBuildConfig() {
		return fmt.Errorf("cannot auto-build '%s': no [container.build] section in config — add a build script or commands, then run 'coi build --profile <profile>'", imageName)
	}

	scriptPath, cleanup, err := resolveBuildScript(&cfg.Container.Build)
	if err != nil {
		return err
	}
	defer cleanup()

	baseImage := cfg.Container.Build.Base
	if baseImage == "" {
		baseImage = image.CoiAlias
	}

	opts := image.BuildOptions{
		ImageType:   "custom",
		AliasName:   imageName,
		Description: fmt.Sprintf("Custom image (%s)", imageName),
		BaseImage:   baseImage,
		BuildScript: scriptPath,
		Force:       false,
		StoragePool: buildPool,
		Logger:      stderrLogFn,
	}

	fmt.Fprintf(os.Stderr, "Building image '%s' (base: %s)...\n", imageName, baseImage)
	result := image.NewBuilder(opts).Build()
	if result.Error != nil {
		return fmt.Errorf("build failed: %w", result.Error)
	}
	if result.Skipped {
		fmt.Fprintf(os.Stderr, "\nImage '%s' already exists — skipping build.\n", imageName)
		return nil
	}
	fmt.Fprintf(os.Stderr, "\nImage '%s' built successfully!\n", imageName)
	if dir, err := coiDataDir(); err == nil {
		image.RecordBuild(dir, imageName, baseImage)
	}
	return nil
}

// coiDataDir returns the path to the ~/.coi directory used for Coi state files.
func coiDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".coi"), nil
}

// CheckAndReportStaleBase checks whether imageName's recorded base was rebuilt
// more recently than imageName itself, and acts according to
// cfg.Container.StaleBaseCheck: "error" returns an error, "warn" prints to
// stderr and continues, "off" does nothing. Missing metadata is always silent.
func CheckAndReportStaleBase(cfg *config.Config, imageName string) error {
	dir, err := coiDataDir()
	if err != nil {
		return nil
	}

	result, stale := image.CheckStaleBase(dir, imageName)
	if !stale {
		return nil
	}

	msg := fmt.Sprintf(
		"image '%s' (built %s) is older than its base '%s' (rebuilt %s) — run 'coi build --profile <profile>' to rebuild",
		result.ChildAlias,
		result.ChildBuiltAt.Format("2006-01-02 15:04 UTC"),
		result.BaseAlias,
		result.BaseBuiltAt.Format("2006-01-02 15:04 UTC"),
	)

	switch cfg.Container.StaleBaseCheck {
	case "error":
		return fmt.Errorf("%s", msg)
	case "off":
		return nil
	default: // "warn" and any unrecognised value
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", msg)
		return nil
	}
}
