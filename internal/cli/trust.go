package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/coipond/coi/internal/session"
	"github.com/spf13/cobra"
)

var trustListFlag bool

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Approve out-of-workspace mounts declared by a project .coi/config.toml",
	Long: `Approve the out-of-workspace host mounts declared by the workspace's
(untrusted) .coi/config.toml.

A project .coi/config.toml is untrusted — it can be supplied by a cloned repo.
Mounts it declares whose host path resolves outside the workspace are ignored at
launch until you approve them here, because a writable mount of a host path (e.g.
your home directory) is a host code-execution vector. In-workspace mounts and
mounts from your trusted ~/.coi/config.toml or $COI_CONFIG are never gated.

The approval is pinned to a fingerprint of the approved mounts. If those mounts
later change (host path, container path, or read-only flag), approval is required
again. Changing unrelated settings (base image, network mode, ...) does not.

For CI/automation, set ` + session.TrustEnvVar + `=1 to bypass the gate. A config
referenced via $COI_CONFIG is trusted, so don't point $COI_CONFIG at an
untrusted repo's own .coi/config.toml.`,
	RunE: app.runTrust,
}

var untrustCmd = &cobra.Command{
	Use:   "untrust",
	Short: "Revoke a trust approval previously granted with 'coi trust'",
	RunE:  app.runUntrust,
}

func init() {
	trustCmd.Flags().BoolVar(&trustListFlag, "list", false, "List trusted project configs and their fingerprints")
}

func (a *App) runTrust(_ *cobra.Command, _ []string) error {
	if trustListFlag {
		return listTrusted()
	}

	absWorkspace, err := filepath.Abs(a.workspace)
	if err != nil {
		return fmt.Errorf("invalid workspace path: %w", err)
	}
	if err := a.overlayWorkspaceConfig(absWorkspace); err != nil {
		return err
	}

	mc, err := ParseMountConfig(a.cfg)
	if err != nil {
		return fmt.Errorf("invalid mount configuration: %w", err)
	}
	sc, err := ParseSocketConfig(a.cfg)
	if err != nil {
		return fmt.Errorf("invalid socket configuration: %w", err)
	}
	cc, err := ParseCredentialConfig(a.cfg)
	if err != nil {
		return fmt.Errorf("invalid credential configuration: %w", err)
	}
	pc := ParsePortConfig(a.cfg)

	sources, err := session.TrustSources(mc, sc, cc, pc, absWorkspace)
	if err != nil {
		return fmt.Errorf("failed to record trust: %w", err)
	}
	if len(sources) == 0 {
		fmt.Fprintln(os.Stderr,
			"Nothing to trust: no project-config mounts resolve outside the workspace, no sockets "+
				"are forwarded, and no ad-hoc credential or port entries are configured.")
		return nil
	}
	for _, s := range sources {
		fmt.Fprintf(os.Stderr, "Trusted out-of-workspace mounts, forwarded sockets, credential entries, and published ports from %s\n", s)
	}
	return nil
}

func listTrusted() error {
	store, err := session.ListTrusted()
	if err != nil {
		return err
	}
	if len(store) == 0 {
		fmt.Fprintln(os.Stderr, "No trusted project configs.")
		return nil
	}
	paths := make([]string, 0, len(store))
	for p := range store {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fp := store[p]
		if len(fp) > 12 {
			fp = fp[:12]
		}
		fmt.Printf("%s  %s\n", fp, p)
	}
	return nil
}

func (a *App) runUntrust(_ *cobra.Command, _ []string) error {
	absWorkspace, err := filepath.Abs(a.workspace)
	if err != nil {
		return fmt.Errorf("invalid workspace path: %w", err)
	}
	if err := a.overlayWorkspaceConfig(absWorkspace); err != nil {
		return err
	}
	mc, err := ParseMountConfig(a.cfg)
	if err != nil {
		return fmt.Errorf("invalid mount configuration: %w", err)
	}
	sc, err := ParseSocketConfig(a.cfg)
	if err != nil {
		return fmt.Errorf("invalid socket configuration: %w", err)
	}
	cc, err := ParseCredentialConfig(a.cfg)
	if err != nil {
		return fmt.Errorf("invalid credential configuration: %w", err)
	}

	// Revoke by the exact stored keys (the loaded SourcePaths), plus the
	// conventional project-config path as a fallback for the case where the
	// config no longer declares the previously-trusted mounts, sockets, or
	// credential entries.
	pc := ParsePortConfig(a.cfg)
	sources := session.UntrustedSourcePaths(mc, sc, cc, pc)
	conventional := filepath.Join(absWorkspace, ".coi", "config.toml")
	if abs, e := filepath.Abs(conventional); e == nil {
		conventional = abs
	}
	if !slices.Contains(sources, conventional) {
		sources = append(sources, conventional)
	}

	n, err := session.UntrustSources(sources)
	if err != nil {
		return fmt.Errorf("failed to update trust store: %w", err)
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "No trust entries found for this workspace.")
		return nil
	}
	fmt.Fprintf(os.Stderr, "Revoked %d trust entr%s for this workspace.\n", n, plural(n))
	return nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
