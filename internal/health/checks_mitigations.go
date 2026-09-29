package health

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// mitigationDisableTokens are kernel command-line flags that turn off CPU
// side-channel mitigations, either wholesale (mitigations=off) or per
// vulnerability class. Exact-token match against the space-separated
// /proc/cmdline fields — these are all complete tokens, not prefixes.
var mitigationDisableTokens = []string{
	"mitigations=off",
	// Meltdown (KPTI)
	"nopti", "pti=off",
	// Spectre v1/v2
	"nospectre_v1", "nospectre_v2", "spectre_v2=off", "spectre_v2_user=off",
	// Speculative store bypass
	"nospec_store_bypass_disable", "spec_store_bypass_disable=off",
	// L1TF / MDS / TAA and friends
	"l1tf=off", "mds=off", "tsx_async_abort=off",
	"retbleed=off", "srbds=off", "mmio_stale_data=off",
	// SMEP/SMAP hardware protections
	"nosmep", "nosmap",
}

// evaluateKernelMitigations is the pure core of CheckKernelMitigations.
func evaluateKernelMitigations(cmdline string) HealthCheck {
	var found []string
	for _, field := range strings.Fields(cmdline) {
		for _, tok := range mitigationDisableTokens {
			if field == tok {
				found = append(found, tok)
				break
			}
		}
	}
	if len(found) == 0 {
		return HealthCheck{
			Name:    "kernel_mitigations",
			Status:  StatusOK,
			Message: "CPU mitigations enabled (no disable flags on the kernel command line)",
		}
	}
	return HealthCheck{
		Name:   "kernel_mitigations",
		Status: StatusWarning,
		Message: fmt.Sprintf(
			"CPU side-channel mitigations disabled on the kernel command line (%s) — Coi containers share the host kernel, so this hands sandboxed code hardware privilege-escalation surface that software patching cannot fix; remove the flag(s) from the bootloader config and reboot",
			strings.Join(found, ", ")),
		Details: map[string]interface{}{
			"flags": found,
		},
	}
}

// CheckKernelMitigations warns when CPU side-channel mitigations are disabled
// on the host kernel command line. The performance win of mitigations=off is
// real, but so is the cost: Coi containers share the host kernel, and Trail of
// Bits' agent-escape report ("VMs won't contain cyber-capable agents") ran its
// escapes on exactly such a host — hardware bugs become exploitable again the
// moment the software mitigations are off. Degrades to OK when the command
// line can't be read.
func CheckKernelMitigations() HealthCheck {
	if runtime.GOOS != "linux" {
		return HealthCheck{
			Name:    "kernel_mitigations",
			Status:  StatusOK,
			Message: fmt.Sprintf("Not applicable (%s)", runtime.GOOS),
		}
	}
	content, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return HealthCheck{
			Name:    "kernel_mitigations",
			Status:  StatusOK,
			Message: "Could not read /proc/cmdline",
		}
	}
	return evaluateKernelMitigations(string(content))
}
