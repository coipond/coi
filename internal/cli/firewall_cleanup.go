package cli

import (
	"fmt"
	"os"

	"github.com/coipond/coi/internal/network"
)

// cleanupContainerFirewall removes every host-side firewall artefact for one
// container: the IP-keyed rule bundle + sets, the IP-keyed monitoring LOG
// rules, and the NAME-keyed IPv6 egress block (removable even when the IP was
// unresolvable — leaked entirely by kill/shutdown before #696). Shared by
// coi kill and coi shutdown so the two reap paths cannot drift again; the
// session teardown in internal/network/manager.go performs the same steps for
// in-session exits.
func cleanupContainerFirewall(name, containerIP string) {
	if containerIP != "" {
		if err := cleanupNftRulesForIP(containerIP); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to cleanup nft rules: %v\n", err)
		}
		if err := cleanupNftMonitoringRulesForIP(containerIP); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to cleanup NFT monitoring rules: %v\n", err)
		}
	}
	if network.NftAvailable() {
		if err := network.RemoveIPv6BlockForContainer(name); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to cleanup IPv6 block rule: %v\n", err)
		}
	}
}
