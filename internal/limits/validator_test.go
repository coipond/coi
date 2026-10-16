package limits

import "testing"

// TestValidateDiskIO is the format matrix for disk I/O limit values. This is
// the authoritative coverage for the syntax; the e2e test
// (tests/limits/test_limits_validation.py) boots ONE container with a
// generous limit to prove end-to-end application, because booting under a
// pathological throttle (e.g. 100kB/s reads) only succeeds when the host page
// cache absorbs the boot I/O — a CI flake, not a validation check.
func TestValidateDiskIO(t *testing.T) {
	valid := []string{
		"", // empty = unlimited
		"10MB",
		"100kB", // SI kilo is lowercase k
		"1GB",
		"1TB",
		"10MiB",
		"100KiB", // IEC kibi is uppercase K
		"1GiB",
		"1TiB",
		"1000iops",
		"1iops",
	}
	for _, io := range valid {
		if err := ValidateDiskIO(io); err != nil {
			t.Errorf("ValidateDiskIO(%q) should be valid, got: %v", io, err)
		}
	}

	invalid := []string{
		"fast",
		"10MB/s", // the /s suffix is documentation-only, not config syntax
		"1000",   // bare number: ambiguous, must carry a unit or iops
		"abc",
		"100KB",  // SI kilo must be lowercase k
		"100kiB", // IEC kibi must be uppercase K
		"10mb",
		"iops",
		"10 MB",
		"-10MB",
		"10.5MB",
	}
	for _, io := range invalid {
		if err := ValidateDiskIO(io); err == nil {
			t.Errorf("ValidateDiskIO(%q) should be rejected", io)
		}
	}
}

// TestValidateDiskSize is the format matrix for the [limits.disk] size quota
// (#728). Unlike disk I/O rates it takes an absolute size and rejects a
// percentage; unlike memory it has no "%" form.
func TestValidateDiskSize(t *testing.T) {
	valid := []string{
		"", // empty = unlimited
		"20GiB",
		"512MiB",
		"1TiB",
		"10GB",
		"500MB",
	}
	for _, s := range valid {
		if err := ValidateDiskSize(s); err != nil {
			t.Errorf("ValidateDiskSize(%q) should be valid, got: %v", s, err)
		}
	}
	invalid := []string{
		"50%",  // percentages are not accepted for an absolute quota
		"1000", // bare number: must carry a unit
		"20 GiB",
		"big",
		"20gib", // IEC gibi must carry uppercase G/i pattern
		"1000iops",
		"-5GiB",
		"10.5GiB",
	}
	for _, s := range invalid {
		if err := ValidateDiskSize(s); err == nil {
			t.Errorf("ValidateDiskSize(%q) should be rejected", s)
		}
	}
}

// TestPoolDriverEnforcesQuota pins which storage drivers can back a rootfs
// size quota. dir MUST be rejected (Incus silently ignores size= there), which
// is what makes coi's hard error correct (#728).
func TestPoolDriverEnforcesQuota(t *testing.T) {
	for _, d := range []string{"btrfs", "zfs", "lvm", "ceph"} {
		if !PoolDriverEnforcesQuota(d) {
			t.Errorf("driver %q should be quota-capable", d)
		}
	}
	for _, d := range []string{"dir", "", "overlay", "unknown"} {
		if PoolDriverEnforcesQuota(d) {
			t.Errorf("driver %q must NOT be treated as quota-capable", d)
		}
	}
}

// The matrices below are the authoritative format coverage for the remaining
// validators — the same consolidation as TestValidateDiskIO. The e2e tests in
// tests/limits/test_limits_validation.py boot ONE container per limit family
// with a representative value; string-syntax acceptance is checked here.

func TestValidateCPUCount(t *testing.T) {
	for _, count := range []string{"", "1", "2", "0-3", "0,1,3", "0-1,3"} {
		if err := ValidateCPUCount(count); err != nil {
			t.Errorf("ValidateCPUCount(%q) should be valid, got: %v", count, err)
		}
	}
	for _, count := range []string{"abc", "1.5", "-1", "1-", "a-b", "0-3,", "1 2"} {
		if err := ValidateCPUCount(count); err == nil {
			t.Errorf("ValidateCPUCount(%q) should be rejected", count)
		}
	}
}

func TestValidateCPUAllowance(t *testing.T) {
	for _, allowance := range []string{"", "50%", "100%", "25ms/100ms", "10ms/50ms"} {
		if err := ValidateCPUAllowance(allowance); err != nil {
			t.Errorf("ValidateCPUAllowance(%q) should be valid, got: %v", allowance, err)
		}
	}
	for _, allowance := range []string{"abc", "200", "50", "25/100", "50 %", "25ms/100"} {
		if err := ValidateCPUAllowance(allowance); err == nil {
			t.Errorf("ValidateCPUAllowance(%q) should be rejected", allowance)
		}
	}
}

func TestValidateMemoryLimit(t *testing.T) {
	for _, limit := range []string{"", "512MiB", "1GiB", "2GB", "50%", "100KiB", "1TiB"} {
		if err := ValidateMemoryLimit(limit); err != nil {
			t.Errorf("ValidateMemoryLimit(%q) should be valid, got: %v", limit, err)
		}
	}
	for _, limit := range []string{"2", "abc", "2XB", "100%%", "512 MiB", "-1GiB"} {
		if err := ValidateMemoryLimit(limit); err == nil {
			t.Errorf("ValidateMemoryLimit(%q) should be rejected", limit)
		}
	}
}

func TestValidateMemorySwap(t *testing.T) {
	for _, swap := range []string{"", "true", "false", "1GiB", "50%"} {
		if err := ValidateMemorySwap(swap); err != nil {
			t.Errorf("ValidateMemorySwap(%q) should be valid, got: %v", swap, err)
		}
	}
	for _, swap := range []string{"yes", "no", "abc", "2XB"} {
		if err := ValidateMemorySwap(swap); err == nil {
			t.Errorf("ValidateMemorySwap(%q) should be rejected", swap)
		}
	}
}

func TestValidateDurationFormats(t *testing.T) {
	for _, duration := range []string{"", "30s", "5m", "2h", "1h30m"} {
		if err := ValidateDuration(duration); err != nil {
			t.Errorf("ValidateDuration(%q) should be valid, got: %v", duration, err)
		}
	}
	for _, duration := range []string{"2x", "-1h", "abc", "100", "0s"} {
		if err := ValidateDuration(duration); err == nil {
			t.Errorf("ValidateDuration(%q) should be rejected", duration)
		}
	}
}

func TestValidatePriorityRange(t *testing.T) {
	for _, priority := range []int{0, 5, 10} {
		if err := ValidatePriority(priority); err != nil {
			t.Errorf("ValidatePriority(%d) should be valid, got: %v", priority, err)
		}
	}
	for _, priority := range []int{-1, 11, 100} {
		if err := ValidatePriority(priority); err == nil {
			t.Errorf("ValidatePriority(%d) should be rejected", priority)
		}
	}
}

func TestValidateMaxProcesses(t *testing.T) {
	for _, maxProc := range []int{0, 1, 1000} {
		if err := ValidateMaxProcesses(maxProc); err != nil {
			t.Errorf("ValidateMaxProcesses(%d) should be valid, got: %v", maxProc, err)
		}
	}
	if err := ValidateMaxProcesses(-1); err == nil {
		t.Error("ValidateMaxProcesses(-1) should be rejected")
	}
}

func TestValidateAllReportsDiskFields(t *testing.T) {
	errs := ValidateAll(
		CPULimits{},
		MemoryLimits{},
		DiskLimits{Read: "fast", Write: "10MB/s", Max: "1000", Size: "50%"},
		RuntimeLimits{},
	)
	for _, field := range []string{"disk.read", "disk.write", "disk.max", "disk.size"} {
		if errs[field] == nil {
			t.Errorf("ValidateAll should report %s as invalid", field)
		}
	}
	if errs["disk.priority"] != nil {
		t.Errorf("ValidateAll should accept default disk priority, got: %v", errs["disk.priority"])
	}
}
