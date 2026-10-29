package health

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestParseDefaultGatewayFromProcRoute(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIP  string
		wantErr bool
	}{
		{
			name: "typical default route",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t00000000\t010080AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			wantIP: "172.128.0.1",
		},
		{
			name: "default route among others",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t000080AC\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
				"eth0\t00000000\t010080AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			wantIP: "172.128.0.1",
		},
		{
			name: "192.168.x gateway",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
			wantIP: "192.168.1.1",
		},
		{
			name: "multiple default routes picks lowest metric",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t00000000\t010080AC\t0003\t0\t0\t64\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0201A8C0\t0003\t0\t0\t0A\t00000000\t0\t0\t0\n",
			wantIP: "192.168.1.2",
		},
		{
			name: "zero gateway skipped",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t010080AC\t0003\t0\t0\t64\t00000000\t0\t0\t0\n",
			wantIP: "172.128.0.1",
		},
		{
			name: "only zero gateway returns error",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n",
			wantErr: true,
		},
		{
			name:    "no default route",
			input:   "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
			wantErr: true,
		},
		{
			name:    "empty content",
			input:   "",
			wantErr: true,
		},
		{
			name:    "header only no newline",
			input:   "Iface\tDestination\tGateway",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDefaultGatewayFromProcRoute(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got IP %q", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.wantIP {
				t.Errorf("got %q, want %q", got, tt.wantIP)
			}
		})
	}
}

func TestParseStorageValueGiB(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		// GiB values (most common)
		{"28.57GiB", 28.57},
		{" 1.35GiB ", 1.35},
		{"0.00GiB", 0},

		// MiB values (fresh pool, the bug trigger)
		{"277.69MiB", 277.69 / 1024},
		{"512.00MiB", 0.5},

		// TiB values (large pools)
		{"2.00TiB", 2048},

		// KiB values (nearly empty)
		{"100.00KiB", 100.0 / (1024 * 1024)},

		// EiB (extreme)
		{"1.00EiB", 1024 * 1024 * 1024},

		// Number only (assume GiB)
		{"42.5", 42.5},

		// Case insensitivity
		{"10.0gib", 10.0},
		{"500.0mib", 500.0 / 1024},
	}

	const (
		absEpsilon = 1e-9
		relEpsilon = 1e-6
	)

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseStorageValueGiB(tt.input)
			tolerance := math.Max(absEpsilon, relEpsilon*math.Abs(tt.want))
			if math.Abs(got-tt.want) > tolerance {
				t.Errorf("parseStorageValueGiB(%q) = %f, want %f", tt.input, got, tt.want)
			}
		})
	}
}

func TestParsePoolInfo(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantDriver string
		wantUsed   float64
		wantTotal  float64
		wantErr    bool
	}{
		{
			name: "dir pool",
			input: `info:
  description: ""
  driver: dir
  name: default
  space used: 1.61GiB
  total space: 28.57GiB
used by: {}`,
			wantDriver: "dir",
			wantUsed:   1.61,
			wantTotal:  28.57,
		},
		{
			name: "zfs pool",
			input: `info:
  description: ""
  driver: zfs
  name: zfs-pool
  space used: 277.69MiB
  total space: 47.94GiB`,
			wantDriver: "zfs",
			wantUsed:   277.69 / 1024,
			wantTotal:  47.94,
		},
		{
			name:    "unparseable output",
			input:   "some error text",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := parsePoolInfo(tt.input)
			if (u.err != nil) != tt.wantErr {
				t.Fatalf("parsePoolInfo() err = %v, wantErr %v", u.err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if u.driver != tt.wantDriver {
				t.Errorf("driver = %q, want %q", u.driver, tt.wantDriver)
			}
			if math.Abs(u.usedGiB-tt.wantUsed) > 1e-6 {
				t.Errorf("usedGiB = %f, want %f", u.usedGiB, tt.wantUsed)
			}
			if math.Abs(u.totalGiB-tt.wantTotal) > 1e-6 {
				t.Errorf("totalGiB = %f, want %f", u.totalGiB, tt.wantTotal)
			}
		})
	}
}

// A pool on the `dir` driver must be flagged as a warning even when its usage
// is fine: with no unpacked image volume to clone from, every launch re-unpacks
// the full image, dominating session startup (#659). CoW drivers stay OK. The
// driver comes primarily from the structured `storage list` JSON; the text
// scrape of `storage info` is only a fallback.
func TestCheckIncusStoragePools_DirDriverWarns(t *testing.T) {
	origGather := gatherPoolUsage
	origList := listPoolDrivers
	defer func() {
		gatherPoolUsage = origGather
		listPoolDrivers = origList
	}()

	tests := []struct {
		name        string
		usage       poolUsage
		listDrivers map[string]string
		wantStatus  CheckStatus
		wantDriver  string
	}{
		{
			name:        "dir driver from structured list warns",
			usage:       poolUsage{usedGiB: 5, totalGiB: 100},
			listDrivers: map[string]string{"testpool": "dir"},
			wantStatus:  StatusWarning,
			wantDriver:  "dir",
		},
		{
			name:       "dir driver via text fallback warns when list unavailable",
			usage:      poolUsage{driver: "dir", usedGiB: 5, totalGiB: 100},
			wantStatus: StatusWarning,
			wantDriver: "dir",
		},
		{
			name:        "dir driver with critical usage stays failed",
			usage:       poolUsage{usedGiB: 99, totalGiB: 100},
			listDrivers: map[string]string{"testpool": "dir"},
			wantStatus:  StatusFailed,
			wantDriver:  "dir",
		},
		{
			name:        "zfs driver with healthy usage is ok",
			usage:       poolUsage{usedGiB: 5, totalGiB: 100},
			listDrivers: map[string]string{"testpool": "zfs"},
			wantStatus:  StatusOK,
			wantDriver:  "zfs",
		},
		{
			name:        "btrfs driver with healthy usage is ok",
			usage:       poolUsage{usedGiB: 5, totalGiB: 100},
			listDrivers: map[string]string{"testpool": "btrfs"},
			wantStatus:  StatusOK,
			wantDriver:  "btrfs",
		},
		{
			name:        "structured list wins over text fallback",
			usage:       poolUsage{driver: "dir", usedGiB: 5, totalGiB: 100},
			listDrivers: map[string]string{"testpool": "zfs"},
			wantStatus:  StatusOK,
			wantDriver:  "zfs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gatherPoolUsage = func(pool string) poolUsage { return tt.usage }
			listPoolDrivers = func() map[string]string { return tt.listDrivers }

			result := CheckIncusStoragePools([]string{"testpool"})
			if result.Status != tt.wantStatus {
				t.Errorf("status = %s, want %s (message: %s)", result.Status, tt.wantStatus, result.Message)
			}

			entry, ok := result.Details["testpool"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected details[testpool] map, got %T", result.Details["testpool"])
			}
			if entry["driver"] != tt.wantDriver {
				t.Errorf("details driver = %v, want %q", entry["driver"], tt.wantDriver)
			}

			// The usage line names the driver so `coi health` text output
			// answers "which driver is this pool on?" at a glance.
			if want := "testpool (" + tt.wantDriver + "):"; !strings.Contains(result.Message, want) {
				t.Errorf("message %q should contain %q", result.Message, want)
			}

			// The usage line must be present (the shared label means the
			// warning alone could otherwise satisfy the Contains above),
			// and the dir warning must follow it.
			usageIdx := strings.Index(result.Message, "GiB free")
			if usageIdx == -1 {
				t.Errorf("usage line missing from message: %q", result.Message)
			}
			if tt.wantDriver == "dir" {
				warnIdx := strings.Index(result.Message, "'dir' storage driver")
				if warnIdx == -1 || warnIdx < usageIdx {
					t.Errorf("dir warning should be present and follow the usage line, message: %q", result.Message)
				}
			}
		})
	}
}

// When the usage query fails, the details entry must still carry the driver
// (known independently via `storage list`) and a dir pool must still surface
// its warning — the schema stays consistent across the error and success
// paths. And since a known driver proves the pool exists, the message must
// say the usage is unavailable rather than contradict itself with "missing".
func TestCheckIncusStoragePools_ErrPathKeepsDriver(t *testing.T) {
	origGather := gatherPoolUsage
	origList := listPoolDrivers
	defer func() {
		gatherPoolUsage = origGather
		listPoolDrivers = origList
	}()

	gatherPoolUsage = func(pool string) poolUsage {
		return poolUsage{err: errors.New("could not parse usage")}
	}
	listPoolDrivers = func() map[string]string {
		return map[string]string{"testpool": "dir"}
	}

	result := CheckIncusStoragePools([]string{"testpool"})
	if result.Status != StatusFailed {
		t.Errorf("status = %s, want %s", result.Status, StatusFailed)
	}

	entry, ok := result.Details["testpool"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected details[testpool] map, got %T", result.Details["testpool"])
	}
	if entry["driver"] != "dir" {
		t.Errorf("details driver = %v, want %q on the error path", entry["driver"], "dir")
	}
	if !strings.Contains(result.Message, "'dir' storage driver") {
		t.Errorf("dir warning should still fire when usage is unavailable, message: %q", result.Message)
	}
	if !strings.Contains(result.Message, "testpool (dir): usage unavailable") {
		t.Errorf("an enumerated pool must report usage unavailable, not missing, message: %q", result.Message)
	}
	if strings.Contains(result.Message, "missing") {
		t.Errorf("a pool with a known driver must not be called missing, message: %q", result.Message)
	}
}

// lvmcluster never gets a thin pool regardless of config; a plain lvm pool
// only loses one when lvm.use_thinpool is explicitly falsy (empty/absent
// defaults to true, same as every other driver).
func TestIsNonThinLVM(t *testing.T) {
	tests := []struct {
		name   string
		driver string
		config map[string]string
		want   bool
	}{
		{"lvm thinpool disabled", "lvm", map[string]string{"lvm.use_thinpool": "false"}, true},
		{"lvm thinpool disabled, alternate spellings", "lvm", map[string]string{"lvm.use_thinpool": "No"}, true},
		{"lvm thinpool default (key absent)", "lvm", map[string]string{}, false},
		{"lvm thinpool explicitly enabled", "lvm", map[string]string{"lvm.use_thinpool": "true"}, false},
		{"lvmcluster ignores an explicit true", "lvmcluster", map[string]string{"lvm.use_thinpool": "true"}, true},
		{"lvmcluster with no config", "lvmcluster", nil, true},
		{"zfs is unaffected", "zfs", map[string]string{"lvm.use_thinpool": "false"}, false},
		{"dir is unaffected", "dir", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNonThinLVM(tt.driver, tt.config); got != tt.want {
				t.Errorf("isNonThinLVM(%q, %v) = %v, want %v", tt.driver, tt.config, got, tt.want)
			}
		})
	}
}

// A non-thin lvm/lvmcluster pool has the same per-launch cost as `dir`
// (#686), and must warn the same way `dir` does, even when its own usage
// is healthy.
func TestCheckIncusStoragePools_NonThinLVMWarns(t *testing.T) {
	origGather := gatherPoolUsage
	origList := listPoolDrivers
	origNonThin := listNonThinLVMPools
	defer func() {
		gatherPoolUsage = origGather
		listPoolDrivers = origList
		listNonThinLVMPools = origNonThin
	}()

	tests := []struct {
		name       string
		driver     string
		nonThin    bool
		wantStatus CheckStatus
		wantWarn   bool
	}{
		{"lvm without a thin pool warns", "lvm", true, StatusWarning, true},
		{"lvmcluster warns", "lvmcluster", true, StatusWarning, true},
		{"lvm with its default thin pool is ok", "lvm", false, StatusOK, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gatherPoolUsage = func(pool string) poolUsage {
				return poolUsage{usedGiB: 5, totalGiB: 100}
			}
			listPoolDrivers = func() map[string]string {
				return map[string]string{"testpool": tt.driver}
			}
			listNonThinLVMPools = func() map[string]bool {
				return map[string]bool{"testpool": tt.nonThin}
			}

			result := CheckIncusStoragePools([]string{"testpool"})
			if result.Status != tt.wantStatus {
				t.Errorf("status = %s, want %s (message: %s)", result.Status, tt.wantStatus, result.Message)
			}

			gotWarn := strings.Contains(result.Message, "full logical-volume copy")
			if gotWarn != tt.wantWarn {
				t.Errorf("non-thin LVM warning present = %v, want %v, message: %q", gotWarn, tt.wantWarn, result.Message)
			}
		})
	}
}

// The usage-error path must still surface the non-thin LVM warning, matching
// the same schema-consistency guarantee the dir case already has.
func TestCheckIncusStoragePools_NonThinLVMErrPathWarns(t *testing.T) {
	origGather := gatherPoolUsage
	origList := listPoolDrivers
	origNonThin := listNonThinLVMPools
	defer func() {
		gatherPoolUsage = origGather
		listPoolDrivers = origList
		listNonThinLVMPools = origNonThin
	}()

	gatherPoolUsage = func(pool string) poolUsage {
		return poolUsage{err: errors.New("could not parse usage")}
	}
	listPoolDrivers = func() map[string]string {
		return map[string]string{"testpool": "lvmcluster"}
	}
	listNonThinLVMPools = func() map[string]bool {
		return map[string]bool{"testpool": true}
	}

	result := CheckIncusStoragePools([]string{"testpool"})
	if result.Status != StatusFailed {
		t.Errorf("status = %s, want %s", result.Status, StatusFailed)
	}
	if !strings.Contains(result.Message, "full logical-volume copy") {
		t.Errorf("non-thin LVM warning should still fire when usage is unavailable, message: %q", result.Message)
	}
}

// A pool with no driver from either source (not enumerated, info failed) is
// genuinely unresolvable — that one is reported as missing.
func TestCheckIncusStoragePools_UnknownPoolIsMissing(t *testing.T) {
	origGather := gatherPoolUsage
	origList := listPoolDrivers
	defer func() {
		gatherPoolUsage = origGather
		listPoolDrivers = origList
	}()

	gatherPoolUsage = func(pool string) poolUsage {
		return poolUsage{err: errors.New("storage pool not found")}
	}
	listPoolDrivers = func() map[string]string { return nil }

	result := CheckIncusStoragePools([]string{"ghostpool"})
	if result.Status != StatusFailed {
		t.Errorf("status = %s, want %s", result.Status, StatusFailed)
	}
	if !strings.Contains(result.Message, "ghostpool: missing") {
		t.Errorf("an unresolvable pool should be reported missing, message: %q", result.Message)
	}
}

func TestEvaluateIncusVersion_AdvisoryWarns(t *testing.T) {
	result := evaluateIncusVersion("Client version: 7.4\nServer version: 7.4")
	if result.Status != StatusWarning {
		t.Fatalf("status = %s, want warning: %s", result.Status, result.Message)
	}
	for _, want := range []string{"7.4", "GHSA-wfvq-qh87-gm4j", "7.5+"} {
		if !strings.Contains(result.Message, want) {
			t.Errorf("message should contain %q, got %q", want, result.Message)
		}
	}
	if ids, _ := result.Details["advisories"].([]string); len(ids) != 1 || ids[0] != "GHSA-wfvq-qh87-gm4j" {
		t.Errorf("details advisories = %v", result.Details["advisories"])
	}

	result = evaluateIncusVersion("Server version: 7.5.1")
	if result.Status != StatusOK || strings.Contains(result.Message, "GHSA-") {
		t.Errorf("7.5.1 should pass without an advisory, got %s: %s", result.Status, result.Message)
	}
}
