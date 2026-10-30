package session

import (
	"strings"
	"testing"
)

// TestSecurityDeviceNamesAreStripped proves the create side and the
// reuse-strip side can't diverge: every security device-name generator produces
// a name that stripSecurityDevicePrefixes will remove on persistent reuse. If a
// new security device family is added, add its generator here — a name whose
// prefix isn't in the strip list would leak the device across reuse (the #610
// class: a stale protected/masked device outliving the config that created it).
func TestSecurityDeviceNamesAreStripped(t *testing.T) {
	cases := map[string]string{
		"protect": pathToDeviceName(".git/hooks"),
		"mask":    maskDeviceName("secrets/.env"),
		"gitc":    commonDirDeviceName("worktree-1"),
		"pin":     pinDeviceName("/workspace/.git"),
	}
	for family, name := range cases {
		stripped := false
		for _, p := range stripSecurityDevicePrefixes {
			if strings.HasPrefix(name, p) {
				stripped = true
				break
			}
		}
		if !stripped {
			t.Errorf("%s device name %q has no prefix in stripSecurityDevicePrefixes %v — "+
				"it would leak across persistent reuse", family, name, stripSecurityDevicePrefixes)
		}
	}
}
