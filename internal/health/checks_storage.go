package health

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/session"
	"github.com/mensfeld/coi/internal/tool"
)

// CheckCOIDirectory verifies the Coi directory exists and is writable
func CheckCOIDirectory() HealthCheck {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return HealthCheck{
			Name:    "coi_directory",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Could not determine home directory: %v", err),
		}
	}

	coiDir := filepath.Join(homeDir, ".coi")

	// Check if directory exists
	info, err := os.Stat(coiDir)
	if os.IsNotExist(err) {
		return HealthCheck{
			Name:    "coi_directory",
			Status:  StatusWarning,
			Message: fmt.Sprintf("%s does not exist (will be created on first run)", coiDir),
		}
	}
	if err != nil {
		return HealthCheck{
			Name:    "coi_directory",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Could not access %s: %v", coiDir, err),
		}
	}

	if !info.IsDir() {
		return HealthCheck{
			Name:    "coi_directory",
			Status:  StatusFailed,
			Message: fmt.Sprintf("%s is not a directory", coiDir),
		}
	}

	// Check if writable by creating a temp file
	testFile := filepath.Join(coiDir, ".health-check-test")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		return HealthCheck{
			Name:    "coi_directory",
			Status:  StatusFailed,
			Message: fmt.Sprintf("%s is not writable", coiDir),
		}
	}
	os.Remove(testFile)

	return HealthCheck{
		Name:    "coi_directory",
		Status:  StatusOK,
		Message: "~/.coi (writable)",
		Details: map[string]interface{}{
			"path": coiDir,
		},
	}
}

// CheckSessionsDirectory verifies the sessions directory exists and is writable
func CheckSessionsDirectory(cfg *config.Config) HealthCheck {
	// Get configured tool to determine sessions directory
	toolName := cfg.Tool.Name
	if toolName == "" {
		toolName = "claude"
	}
	toolInstance, err := tool.Get(toolName)
	if err != nil {
		toolInstance = tool.GetDefault()
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return HealthCheck{
			Name:    "sessions_directory",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Could not determine home directory: %v", err),
		}
	}

	baseDir := filepath.Join(homeDir, ".coi")
	sessionsDir := session.GetSessionsDir(baseDir, toolInstance)

	// Check if directory exists
	info, err := os.Stat(sessionsDir)
	if os.IsNotExist(err) {
		return HealthCheck{
			Name:    "sessions_directory",
			Status:  StatusOK,
			Message: fmt.Sprintf("%s (will be created)", filepath.Base(sessionsDir)),
			Details: map[string]interface{}{
				"path": sessionsDir,
			},
		}
	}
	if err != nil {
		return HealthCheck{
			Name:    "sessions_directory",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Could not access %s: %v", sessionsDir, err),
		}
	}

	if !info.IsDir() {
		return HealthCheck{
			Name:    "sessions_directory",
			Status:  StatusFailed,
			Message: fmt.Sprintf("%s is not a directory", sessionsDir),
		}
	}

	// Check if writable
	testFile := filepath.Join(sessionsDir, ".health-check-test")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		return HealthCheck{
			Name:    "sessions_directory",
			Status:  StatusFailed,
			Message: fmt.Sprintf("%s is not writable", sessionsDir),
		}
	}
	os.Remove(testFile)

	return HealthCheck{
		Name:    "sessions_directory",
		Status:  StatusOK,
		Message: fmt.Sprintf("~/.coi/%s (writable)", filepath.Base(sessionsDir)),
		Details: map[string]interface{}{
			"path": sessionsDir,
		},
	}
}

// CheckDiskSpace checks available disk space in ~/.coi directory
func CheckDiskSpace() HealthCheck {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return HealthCheck{
			Name:    "disk_space",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not determine home directory: %v", err),
		}
	}

	coiDir := filepath.Join(homeDir, ".coi")

	// Use the parent directory if .coi doesn't exist yet
	checkDir := coiDir
	if _, err := os.Stat(coiDir); os.IsNotExist(err) {
		checkDir = homeDir
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(checkDir, &stat); err != nil {
		return HealthCheck{
			Name:    "disk_space",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not check disk space: %v", err),
		}
	}

	// Calculate available space in bytes
	// #nosec G115 - Bsize is always positive on real filesystems
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	availableGB := float64(availableBytes) / (1024 * 1024 * 1024)

	// Warn if less than 5GB available
	if availableGB < 5 {
		return HealthCheck{
			Name:    "disk_space",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Low disk space: %.1f GB available", availableGB),
			Details: map[string]interface{}{
				"available_gb": availableGB,
				"path":         checkDir,
			},
		}
	}

	return HealthCheck{
		Name:    "disk_space",
		Status:  StatusOK,
		Message: fmt.Sprintf("%.1f GB available", availableGB),
		Details: map[string]interface{}{
			"available_gb": availableGB,
			"path":         checkDir,
		},
	}
}

// defaultIncusPool returns the storage pool name used by Incus's "default"
// profile. Used as a fallback when no profile/global config asks for a
// specific pool, so we still check something useful. Goes through
// container.IncusOutput so the configured Incus project is respected.
func defaultIncusPool() string {
	profileOut, err := container.IncusOutput("profile", "show", "default")
	if err != nil {
		return "default"
	}
	for _, line := range strings.Split(profileOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pool:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "pool:"))
		}
	}
	return "default"
}

// poolUsage holds parsed `incus storage info` numbers for a single pool plus
// any error encountered while gathering them.
type poolUsage struct {
	driver   string
	usedGiB  float64
	totalGiB float64
	err      error
}

// parsePoolInfo extracts the driver and usage numbers from `incus storage
// info` output.
func parsePoolInfo(out string) poolUsage {
	var u poolUsage
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "driver:"):
			u.driver = strings.TrimSpace(strings.TrimPrefix(line, "driver:"))
		case strings.HasPrefix(line, "space used:"):
			u.usedGiB = parseStorageValueGiB(strings.TrimPrefix(line, "space used:"))
		case strings.HasPrefix(line, "total space:"):
			u.totalGiB = parseStorageValueGiB(strings.TrimPrefix(line, "total space:"))
		}
	}

	if u.totalGiB == 0 {
		u.err = fmt.Errorf("could not parse usage")
	}
	return u
}

// isNonThinLVM reports whether an lvm/lvmcluster pool lacks a thin pool, so
// every launch does a full logical-volume copy instead of a CoW clone, the
// same per-launch cost `dir` has (#686).
func isNonThinLVM(driver string, config map[string]string) bool {
	switch driver {
	case "lvmcluster":
		return true
	case "lvm":
		switch strings.ToLower(config["lvm.use_thinpool"]) {
		case "false", "0", "no", "off":
			return true
		}
	}
	return false
}

// CheckIncusStoragePools checks Incus storage pool usage for all pools the
// loaded config references (global + every profile), de-duplicated. An empty
// pool name in config falls back to the Incus default profile's pool so we
// always check at least one real pool.
//
// One HealthCheck is returned with per-pool entries in Details. The overall
// status is the worst status across the inspected pools (failed > warning > ok).
// Besides usage thresholds, a pool on the `dir` driver is flagged as a warning:
// it forces `incus init` to re-unpack the whole image on every launch, which
// dominates session startup time (#659). A non-thin lvm/lvmcluster pool gets
// the same warning for the same reason (#686).
func CheckIncusStoragePools(pools []string) HealthCheck {
	// De-dupe + replace empty entries with the actual default pool name.
	seen := map[string]bool{}
	var unique []string
	for _, p := range pools {
		if p == "" {
			p = defaultIncusPool()
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		unique = append(unique, p)
	}
	if len(unique) == 0 {
		unique = []string{defaultIncusPool()}
	}

	details := map[string]interface{}{}
	overall := StatusOK
	var messages []string
	worsen := func(s CheckStatus) {
		if s == StatusFailed {
			overall = StatusFailed
		} else if s == StatusWarning && overall == StatusOK {
			overall = StatusWarning
		}
	}

	drivers := listPoolDrivers()
	nonThinLVM := listNonThinLVMPools()

	for _, pool := range unique {
		u := gatherPoolUsage(pool)

		// Driver primarily from the structured list; the text scrape is a
		// fallback. An empty driver after both means "unknown" — it is kept
		// as "" in the details so consumers can see driver detection failed.
		driver := drivers[pool]
		if driver == "" {
			driver = u.driver
		}

		status, msgs, entry := evaluatePool(pool, driver, u, nonThinLVM[pool])
		worsen(status)
		details[pool] = entry
		messages = append(messages, msgs...)
	}

	return HealthCheck{
		Name:    "incus_storage_pools",
		Status:  overall,
		Message: strings.Join(messages, "; "),
		Details: details,
	}
}

// evaluatePool turns one pool's driver + gathered usage into its status,
// message lines, and details entry. Both the usage-error and success paths
// flow through here, so driver-based diagnoses (the dir warning, the
// non-thin LVM warning, #686) cannot drift between the two paths.
func evaluatePool(pool, driver string, u poolUsage, nonThinLVM bool) (CheckStatus, []string, map[string]interface{}) {
	label := pool
	if driver != "" {
		label = fmt.Sprintf("%s (%s)", pool, driver)
	}

	var status CheckStatus
	var msgs []string
	var entry map[string]interface{}

	if u.err != nil {
		status = StatusFailed
		entry = map[string]interface{}{
			"driver": driver,
			"status": string(StatusFailed),
			"error":  u.err.Error(),
		}
		if driver != "" {
			// A known driver means the pool was enumerated (or its info
			// output partially parsed) — it exists, only the usage query
			// failed. Calling it "missing" would contradict the driver we
			// are about to print.
			msgs = append(msgs, fmt.Sprintf("%s: usage unavailable: %v", label, u.err))
		} else {
			msgs = append(msgs, fmt.Sprintf("%s: missing", pool))
		}
	} else {
		freeGiB := u.totalGiB - u.usedGiB
		usedPct := (u.usedGiB / u.totalGiB) * 100

		switch {
		case freeGiB < 2 || usedPct > 90:
			status = StatusFailed
		case freeGiB < 5 || usedPct > 80:
			status = StatusWarning
		default:
			status = StatusOK
		}
		if (driver == "dir" || nonThinLVM) && status == StatusOK {
			status = StatusWarning
		}

		entry = map[string]interface{}{
			"driver":    driver,
			"used_gib":  u.usedGiB,
			"total_gib": u.totalGiB,
			"free_gib":  freeGiB,
			"used_pct":  usedPct,
			"status":    string(status),
		}
		msgs = append(msgs, fmt.Sprintf("%s: %.1f GiB free of %.1f GiB (%.0f%% used)", label, freeGiB, u.totalGiB, usedPct))
	}

	if driver == "dir" {
		// A `dir` pool has no unpacked image volume to clone from, so every
		// launch re-unpacks the full image tarball (~5-6s per unpacked GB,
		// #659). Copy-on-write drivers make instance creation near-free.
		msgs = append(msgs, fmt.Sprintf("%s: 'dir' storage driver re-unpacks the image on every launch — recreate the pool with a copy-on-write driver (zfs/btrfs), e.g. by re-running install.sh", label))
	} else if nonThinLVM {
		// Same per-launch cost as `dir`, just reached through LVM instead of
		// the driver name: no thin pool means no CoW clone (#686).
		reason := "lvm.use_thinpool is disabled"
		if driver == "lvmcluster" {
			reason = "clustered LVM pools never use a thin pool"
		}
		msgs = append(msgs, fmt.Sprintf("%s: %s, so every launch does a full logical-volume copy instead of a thin-provisioned clone: recreate the pool with lvm.use_thinpool enabled or a copy-on-write driver (zfs/btrfs)", label, reason))
	}

	return status, msgs, entry
}

// parseStorageValueGiB parses a value like "277.69MiB" or "28.57GiB" and
// returns the equivalent in GiB. Returns 0 on parse failure.
func parseStorageValueGiB(s string) float64 {
	s = strings.TrimSpace(s)

	// Find where the numeric part ends and the unit suffix begins.
	// We cannot use fmt.Sscanf("%f%s") because it interprets "1.00EiB"
	// as scientific notation (the 'E') and fails.
	i := 0
	for i < len(s) && (s[i] == '.' || s[i] == '-' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	if i == 0 {
		return 0
	}

	var val float64
	if _, err := fmt.Sscanf(s[:i], "%f", &val); err != nil {
		return 0
	}

	unit := strings.TrimSpace(s[i:])
	switch strings.ToLower(unit) {
	case "eib":
		return val * 1024 * 1024 * 1024
	case "tib":
		return val * 1024
	case "gib", "":
		return val
	case "mib":
		return val / 1024
	case "kib":
		return val / (1024 * 1024)
	case "bytes", "b":
		return val / (1024 * 1024 * 1024)
	default:
		return val // unknown unit, assume GiB
	}
}
