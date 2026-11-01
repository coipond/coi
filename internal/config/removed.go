package config

import (
	"fmt"
	"os"
)

// warnRemovedNetworkLogging reports a [network.logging] section in path. The
// section was removed (nothing ever wrote its log) and is ignored, so files
// that still set it keep loading.
func warnRemovedNetworkLogging(path string) {
	fmt.Fprintf(os.Stderr,
		"WARNING: ignoring [network.logging] in %s; the section was removed and "+
			"never had an effect. Use [monitoring.nft] for network threat events.\n", path)
}

// DropRemovedProfileKeys deletes removed sections from a decoded profile so
// schema validation (additionalProperties: false) does not reject a profile
// that still sets them, and warns about each one found, naming path.
func DropRemovedProfileKeys(raw map[string]any, path string) {
	network, ok := raw["network"].(map[string]any)
	if !ok {
		return
	}
	if _, ok := network["logging"]; !ok {
		return
	}
	delete(network, "logging")
	warnRemovedNetworkLogging(path)
}
