package cli

import (
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/alias"
	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/network"
	"github.com/spf13/cobra"
)

// hostsCmd is the parent for runtime /etc/hosts management (#605).
var hostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "Manage a running container's /etc/hosts entries",
	Long: `Add, list, or remove static host entries in a running container's /etc/hosts,
with firewall reachability applied to match the container's network mode.

For entries that should always be present, declare them in config instead:

  [[network.hosts]]
  ip        = "10.0.0.5"
  hostnames = ["db.internal"]

Entries added here are session-scoped — they are gone when the container stops.
Run with the same network config the container was launched with, so the firewall
reachability matches its mode.

Examples:
  coi hosts add coi-abc12345-1 10.0.0.5 db.internal cache.internal
  coi hosts list coi-abc12345-1
  coi hosts remove coi-abc12345-1 db.internal`,
}

var hostsAddCmd = &cobra.Command{
	Use:   "add <container> <ip> <hostname> [hostname...]",
	Short: "Add a host entry to a running container",
	Args:  cobra.MinimumNArgs(3),
	RunE:  app.hostsAddCommand,
}

var hostsListCmd = &cobra.Command{
	Use:   "list <container>",
	Short: "List a running container's coi-managed host entries",
	Args:  cobra.ExactArgs(1),
	RunE:  app.hostsListCommand,
}

var hostsRemoveCmd = &cobra.Command{
	Use:   "remove <container> <hostname> [hostname...]",
	Short: "Remove host entries from a running container",
	Args:  cobra.MinimumNArgs(2),
	RunE:  app.hostsRemoveCommand,
}

func init() {
	hostsAddCmd.Flags().IntSlice("ports", nil,
		"restrict this host to these TCP/UDP ports (e.g. --ports 443); empty inherits allowed_ports (else all)")
	hostsCmd.AddCommand(hostsAddCmd, hostsListCmd, hostsRemoveCmd)
}

// resolveRunningContainer maps an alias or container name to an existing
// container name.
func resolveRunningContainer(arg string) (string, error) {
	name := arg
	if resolved, err := alias.ResolveAliasForRunning(arg); err == nil {
		name = resolved
	} else if !alias.IsContainerName(arg) {
		return "", fmt.Errorf("%q is not a known container or alias", arg)
	}
	exists, err := container.NewManager(name).Exists()
	if err != nil {
		return "", fmt.Errorf("failed to check container %q: %w", name, err)
	}
	if !exists {
		return "", fmt.Errorf("container %q not found", name)
	}
	return name, nil
}

func (a *App) hostsAddCommand(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	name, err := resolveRunningContainer(args[0])
	if err != nil {
		return err
	}
	ports, err := cmd.Flags().GetIntSlice("ports")
	if err != nil {
		return err
	}
	entry := config.HostEntry{IP: args[1], Hostnames: args[2:], Ports: ports}
	if err := network.AddUserHost(name, a.cfg.Network.Mode, config.BoolVal(a.cfg.Network.AllowLocalNetworkAccess), entry, a.cfg.Network.AllowedPorts); err != nil {
		return err
	}
	scope := ""
	if len(ports) > 0 {
		scope = fmt.Sprintf(" (ports %v)", ports)
	}
	fmt.Printf("Added %s -> %s%s to %s\n", strings.Join(entry.Hostnames, " "), entry.IP, scope, name)
	return nil
}

func (a *App) hostsListCommand(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	name, err := resolveRunningContainer(args[0])
	if err != nil {
		return err
	}
	entries, err := network.ReadUserHosts(name)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Printf("No coi-managed host entries in %s\n", name)
		return nil
	}
	for _, e := range entries {
		fmt.Printf("%s\t%s\n", e.IP, strings.Join(e.Hostnames, " "))
	}
	return nil
}

func (a *App) hostsRemoveCommand(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	name, err := resolveRunningContainer(args[0])
	if err != nil {
		return err
	}
	kept, err := network.RemoveUserHost(name, args[1:])
	if err != nil {
		return err
	}
	fmt.Printf("Removed %s from %s; %d entr(y/ies) remain\n", strings.Join(args[1:], " "), name, len(kept))
	return nil
}
