package cli

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
	}{
		// Equal versions
		{"0.7.0", "0.7.0", 0},
		{"1.0.0", "1.0.0", 0},

		// a < b
		{"0.7.0", "0.8.0", -1},
		{"0.7.0", "1.0.0", -1},
		{"0.7.9", "0.8.0", -1},
		{"0.9.0", "0.10.0", -1},
		{"1.2.3", "1.2.4", -1},

		// a > b
		{"0.8.0", "0.7.0", 1},
		{"1.0.0", "0.7.0", 1},
		{"0.10.0", "0.9.0", 1},
		{"1.2.4", "1.2.3", 1},

		// Different lengths
		{"0.7", "0.7.0", 0},
		{"0.7", "0.7.1", -1},
		{"0.7.1", "0.7", 1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			result := compareVersions(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestNormalizeVersion locks down that a version string is reduced to a bare
// number regardless of how many leading 'v' characters a build injected.
// Regression guard for the release-build bug where the Makefile's `?=` skipped
// its `sed 's/^v//'`, leaving Version="v0.10.1" and rendering as "vv0.10.1".
func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"0.10.1", "0.10.1"},
		{"v0.10.1", "0.10.1"},
		{"vv0.10.1", "0.10.1"}, // the doubled-prefix release artifact
		{"dev", "dev"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeVersion(tt.in); got != tt.want {
				t.Errorf("normalizeVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestCompareVersionsToleratesVPrefix reproduces the user-visible failure: a
// v-prefixed current version made compareVersions fall into string comparison
// ("v0" > "0"), so `coi update` wrongly reported "already on the latest version"
// for 0.10.1 when 0.11.0 was out. Normalized inputs must compare numerically.
func TestCompareVersionsToleratesVPrefix(t *testing.T) {
	if got := compareVersions(normalizeVersion("vv0.10.1"), normalizeVersion("v0.11.0")); got != -1 {
		t.Errorf("compareVersions(vv0.10.1, v0.11.0) after normalize = %d, want -1 (update available)", got)
	}
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("hello world\n")
	// SHA256 of "hello world\n"
	checksumFile := []byte("a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447  test-binary\n")

	t.Run("valid checksum", func(t *testing.T) {
		err := verifyChecksum(data, checksumFile, "test-binary")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("wrong binary name", func(t *testing.T) {
		err := verifyChecksum(data, checksumFile, "wrong-name")
		if err == nil {
			t.Error("expected error for wrong binary name")
		}
	})

	t.Run("tampered data", func(t *testing.T) {
		tamperedData := []byte("tampered\n")
		err := verifyChecksum(tamperedData, checksumFile, "test-binary")
		if err == nil {
			t.Error("expected error for tampered data")
		}
	})

	t.Run("single space separator", func(t *testing.T) {
		checksumSingleSpace := []byte("a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447 test-binary\n")
		err := verifyChecksum(data, checksumSingleSpace, "test-binary")
		if err != nil {
			t.Errorf("expected no error with single space separator, got: %v", err)
		}
	})

	t.Run("empty checksums file", func(t *testing.T) {
		err := verifyChecksum(data, []byte(""), "test-binary")
		if err == nil {
			t.Error("expected error for empty checksums file")
		}
	})
}

func TestRestoreCapability(t *testing.T) {
	// Create a temporary file to act as a fake binary
	tmpFile, err := os.CreateTemp("", "coi-test-cap-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// restoreCapability should not panic regardless of platform
	t.Run("does not panic", func(t *testing.T) {
		restoreCapability(tmpFile.Name())
	})

	if runtime.GOOS != "linux" {
		t.Run("no-op on non-linux", func(t *testing.T) {
			// On non-Linux, restoreCapability returns immediately.
			// Just verify it completes without error.
			restoreCapability("/nonexistent/path")
		})
	}
}

func TestInstalledFromPackage(t *testing.T) {
	orig := InstallSource
	defer func() { InstallSource = orig }()

	// Only a plain source build may self-update. Every package format owns its
	// installed files, so anything else must be treated as packaged — including
	// formats with no entry in packageUpdateCommands.
	cases := map[string]bool{
		"source":  false,
		"deb":     true,
		"rpm":     true,
		"arch":    true,
		"brew":    true,
		"portage": true, // deliberately unmapped
	}
	for src, want := range cases {
		InstallSource = src
		if got := installedFromPackage(); got != want {
			t.Errorf("InstallSource=%q: got %v, want %v", src, got, want)
		}
	}
}

func TestPackagedUpdateHint(t *testing.T) {
	orig := InstallSource
	defer func() { InstallSource = orig }()

	// A mapped format names its own tool and no other.
	for src, want := range map[string]string{"deb": "apt", "rpm": "dnf", "arch": "pacman"} {
		InstallSource = src
		hint := packagedUpdateHint()
		if !strings.Contains(hint, want) {
			t.Errorf("InstallSource=%q: hint should name %q, got: %s", src, want, hint)
		}
		for other, tool := range map[string]string{"deb": "apt ", "rpm": "dnf ", "arch": "pacman "} {
			if other != src && strings.Contains(hint, tool) {
				t.Errorf("InstallSource=%q: hint wrongly suggests %q: %s", src, tool, hint)
			}
		}
	}

	// An unmapped format must still get guidance, not advice for the wrong tool.
	InstallSource = "portage"
	hint := packagedUpdateHint()
	if strings.Contains(hint, "apt") || strings.Contains(hint, "dnf") {
		t.Errorf("unmapped source must not name a specific tool, got: %s", hint)
	}
	if !strings.Contains(hint, "package manager") {
		t.Errorf("unmapped source must still give guidance, got: %s", hint)
	}
}

// A package-managed binary must never be overwritten in place: that desyncs the
// package manager's file database and the next system upgrade reverts it. The
// refusal has to happen before any network call, and --force must not bypass it.
func TestUpdateCoreRefusesPackagedInstall(t *testing.T) {
	origSource, origCheck, origForce := InstallSource, updateCheck, updateForce
	defer func() {
		InstallSource, updateCheck, updateForce = origSource, origCheck, origForce
	}()

	for _, src := range []string{"deb", "rpm", "portage"} {
		InstallSource = src
		updateCheck = false
		updateForce = true // deliberately not an escape hatch

		err := updateCoreCommand(updateCoreCmd, nil)
		if err == nil {
			t.Fatalf("InstallSource=%q self-updated; must refuse even with --force", src)
		}
		if !strings.Contains(err.Error(), "package manager") {
			t.Errorf("InstallSource=%q: refusal must point at the package manager, got: %v", src, err)
		}
	}
}
