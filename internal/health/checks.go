package health

import (
	"github.com/coipond/coi/internal/container"
)

// gatherPoolUsage queries `incus storage info <pool>` and parses out the
// driver and space-used / total-space lines. Returns an error if the pool is
// missing or the output cannot be parsed. Goes through container.IncusOutput
// so the configured Incus project is respected. Swappable so unit tests can
// exercise CheckIncusStoragePools without an Incus daemon.
var gatherPoolUsage = func(pool string) poolUsage {
	out, err := container.IncusOutput("storage", "info", pool)
	if err != nil {
		return poolUsage{err: err}
	}
	return parsePoolInfo(out)
}

// listPoolDrivers returns a pool-name → driver map from `incus storage list
// --format=json` — the structured source of truth for the driver. The text
// scrape in parsePoolInfo stays only as a fallback, so a future Incus
// reshaping either output cannot silently blank the driver. Returns nil when
// the list call fails; swappable so unit tests can run without a daemon.
var listPoolDrivers = func() map[string]string {
	pools, err := container.ListStoragePools()
	if err != nil {
		return nil
	}
	drivers := make(map[string]string, len(pools))
	for _, p := range pools {
		drivers[p.Name] = p.Driver
	}
	return drivers
}

// listNonThinLVMPools returns pool names flagged by isNonThinLVM, read from
// the same `storage list --format=json` call listPoolDrivers already makes.
var listNonThinLVMPools = func() map[string]bool {
	pools, err := container.ListStoragePools()
	if err != nil {
		return nil
	}
	nonThin := make(map[string]bool)
	for _, p := range pools {
		if isNonThinLVM(p.Driver, p.Config) {
			nonThin[p.Name] = true
		}
	}
	return nonThin
}
