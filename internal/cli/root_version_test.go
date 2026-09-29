package cli

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

// TestRootVersionFlagOutput guards the `coi --version` (cobra version flag)
// display path: it must render the same "Coi (Code on Incus) v<semver>" line as
// the `coi version` subcommand and be normalized, so a stray or doubled 'v' from
// a mis-tagged release build (e.g. "vv0.10.1") can't leak here either. It renders
// through the real shared template (rootVersionTemplate) + normalizeVersion.
func TestRootVersionFlagOutput(t *testing.T) {
	tests := []struct {
		in       string
		wantLine string
	}{
		{"0.11.0", "Coi (Code on Incus) v0.11.0\n"},
		{"v0.11.0", "Coi (Code on Incus) v0.11.0\n"},
		{"vv0.10.1", "Coi (Code on Incus) v0.10.1\n"}, // the doubled-prefix build artifact
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			cmd := &cobra.Command{
				Use:     "coi",
				Version: normalizeVersion(tt.in),
				Run:     func(*cobra.Command, []string) {},
			}
			cmd.SetVersionTemplate(rootVersionTemplate)
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"--version"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute(--version): %v", err)
			}
			if got := buf.String(); got != tt.wantLine {
				t.Errorf("coi --version for injected %q = %q, want %q", tt.in, got, tt.wantLine)
			}
		})
	}
}

// TestRootCmdVersionWiring guards that the real rootCmd is actually wired to
// normalize its version and use the shared template, so the fix for the
// doubled-'v' leak into `coi --version` can't be silently reverted.
func TestRootCmdVersionWiring(t *testing.T) {
	if rootCmd.Version != normalizeVersion(Version) {
		t.Errorf("rootCmd.Version = %q, want normalizeVersion(Version) = %q",
			rootCmd.Version, normalizeVersion(Version))
	}
	if got := rootCmd.VersionTemplate(); got != rootVersionTemplate {
		t.Errorf("rootCmd version template = %q, want %q", got, rootVersionTemplate)
	}
}
