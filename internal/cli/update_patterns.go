package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var updatePatternsCmd = &cobra.Command{
	Use:   "patterns",
	Short: "Clone or update the GTFOBins and Sigma detection databases",
	Long: `Clone (or update) the GTFOBins reverse-shell database and the Sigma
linux/process_creation rule database used by each container's security monitor.

Both databases are stored locally. A container's monitor loads them when the
container starts, so containers started from now on use the updated databases;
running containers, and new sessions that reuse them, keep the previous ones
until they stop. Restart a running container to apply the update to it.

Source URLs and local directories are configured in ~/.coi/config.toml under
the [detection] section:

  [detection]
  gtfobins_source = "https://github.com/GTFOBins/GTFOBins.github.io.git"
  gtfobins_dir    = "~/.coi/gtfobins"
  sigma_source    = "https://github.com/SigmaHQ/sigma.git"
  sigma_dir       = "~/.coi/sigma"

On first run each repository is cloned from the configured source URL. On
subsequent runs git pull (GTFOBins) or git pull (Sigma) updates the existing
clone. The Sigma clone uses a sparse, blobless checkout that fetches only the
rules/linux/process_creation/ subtree (~300 KB).

Examples:
  coi update patterns            # clone/update both databases
  coi update patterns --dry-run  # show what would be done, don't execute
`,
	RunE: updatePatternsCommand,
}

func init() {
	updatePatternsCmd.Flags().Bool("dry-run", false, "Print git commands that would run, without executing them")
}

func updatePatternsCommand(cmd *cobra.Command, _ []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not determine home directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".coi"), 0o755); err != nil {
		return fmt.Errorf("could not create ~/.coi: %w", err)
	}

	gtfobinsSource := app.cfg.Detection.GTFOBinsSource
	gtfobinsDir := app.cfg.Detection.GTFOBinsDir
	sigmaSource := app.cfg.Detection.SigmaSource
	sigmaDir := app.cfg.Detection.SigmaDir

	fmt.Println("=== GTFOBins ===")
	if err := updateGTFOBins(gtfobinsDir, gtfobinsSource, dryRun); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("=== Sigma ===")
	if err := updateSigma(sigmaDir, sigmaSource, dryRun); err != nil {
		return err
	}

	if !dryRun {
		fmt.Println()
		fmt.Println("Done. Containers started from now on use the updated patterns and rules; running containers keep the previous ones until they stop.")
	}
	return nil
}

func updateGTFOBins(cloneDir, sourceURL string, dryRun bool) error {
	if _, err := os.Stat(filepath.Join(cloneDir, ".git")); err == nil {
		gitArgs := []string{"-C", cloneDir, "pull", "--ff-only", "--depth=1"}
		fmt.Printf("Updating GTFOBins database at %s...\n", cloneDir)
		if dryRun {
			fmt.Printf("[dry-run] git %v\n", gitArgs)
			return nil
		}
		out, err := runGit(gitArgs...)
		if out != "" {
			fmt.Print(out)
		}
		if err != nil {
			return fmt.Errorf("git failed: %w", err)
		}
	} else if _, err := os.Stat(cloneDir); err == nil {
		return fmt.Errorf(
			"%s exists but is not a git repository; remove it and re-run to clone fresh",
			cloneDir,
		)
	} else {
		gitArgs := []string{"clone", "--depth=1", sourceURL, cloneDir}
		fmt.Printf("Cloning GTFOBins database from %s to %s...\n", sourceURL, cloneDir)
		if dryRun {
			fmt.Printf("[dry-run] git %v\n", gitArgs)
			return nil
		}
		out, err := runGit(gitArgs...)
		if out != "" {
			fmt.Print(out)
		}
		if err != nil {
			return fmt.Errorf("git failed: %w", err)
		}
	}
	return nil
}

func updateSigma(cloneDir, sourceURL string, dryRun bool) error {
	if _, err := os.Stat(filepath.Join(cloneDir, ".git")); err == nil {
		gitArgs := []string{"-C", cloneDir, "pull", "--ff-only", "--depth=1"}
		fmt.Printf("Updating Sigma database at %s...\n", cloneDir)
		if dryRun {
			fmt.Printf("[dry-run] git %v\n", gitArgs)
			return nil
		}
		out, err := runGit(gitArgs...)
		if out != "" {
			fmt.Print(out)
		}
		if err != nil {
			return fmt.Errorf("git failed: %w", err)
		}
	} else if _, err := os.Stat(cloneDir); err == nil {
		return fmt.Errorf(
			"%s exists but is not a git repository; remove it and re-run to clone fresh",
			cloneDir,
		)
	} else {
		cloneArgs := []string{"clone", "--depth=1", "--filter=blob:none", "--sparse", sourceURL, cloneDir}
		sparseArgs := []string{"-C", cloneDir, "sparse-checkout", "set", "rules/linux/process_creation"}
		fmt.Printf("Cloning Sigma database from %s to %s...\n", sourceURL, cloneDir)
		if dryRun {
			fmt.Printf("[dry-run] git %v\n", cloneArgs)
			fmt.Printf("[dry-run] git %v\n", sparseArgs)
			return nil
		}
		out, err := runGit(cloneArgs...)
		if out != "" {
			fmt.Print(out)
		}
		if err != nil {
			return fmt.Errorf("git clone failed: %w", err)
		}
		out, err = runGit(sparseArgs...)
		if out != "" {
			fmt.Print(out)
		}
		if err != nil {
			return fmt.Errorf("git sparse-checkout failed: %w", err)
		}
	}
	return nil
}

// runGit runs git with the given arguments and returns combined output.
func runGit(args ...string) (string, error) {
	c := exec.Command("git", args...)
	out, err := c.CombinedOutput()
	return string(out), err
}
