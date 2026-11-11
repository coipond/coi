package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/spf13/pflag"
)

func TestCommandNeedsAllProfiles(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"shell"}, false},
		{[]string{"run"}, false},
		{[]string{"top"}, false},
		{[]string{"list"}, false},
		{[]string{"container", "list"}, false},
		{[]string{"container", "exec"}, false},
		{[]string{"profile", "list"}, true},
		{[]string{"profile", "show"}, true},
		{[]string{"health"}, true},
		{[]string{"build"}, true},
		{[]string{"clean"}, true},
		{[]string{"validate", "profile"}, true},
	}
	for _, tt := range tests {
		cmd, _, err := rootCmd.Find(tt.args)
		if err != nil {
			t.Fatalf("Find(%v): %v", tt.args, err)
		}
		if got := commandNeedsAllProfiles(cmd); got != tt.want {
			t.Errorf("commandNeedsAllProfiles(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
	if commandNeedsAllProfiles(rootCmd) {
		t.Error("bare coi runs coi shell and needs one profile")
	}
}

// executeWithProfiles runs `coi <args>` with a temp HOME holding the given
// ~/.coi/profiles/<name>/config.toml files and an optional ~/.coi/config.toml.
func executeWithProfiles(t *testing.T, profiles map[string]string, userConfig string, args ...string) error {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("COI_CONFIG", "")
	t.Chdir(t.TempDir())
	for name, content := range profiles {
		dir := filepath.Join(home, ".coi", "profiles", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if userConfig != "" {
		if err := os.MkdirAll(filepath.Join(home, ".coi"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".coi", "config.toml"), []byte(userConfig), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Execute zeroes app and parses flags into it: reset both for later tests.
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		reset := func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
		rootCmd.PersistentFlags().VisitAll(reset)
		if cmd, _, err := rootCmd.Find(args); err == nil {
			cmd.Flags().VisitAll(reset)
		}
	})
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	rootCmd.SetOut(devNull)
	defer rootCmd.SetOut(nil)
	rootCmd.SetArgs(args)
	return Execute()
}

const brokenProfile = "[container\nimage = \n"

func TestExecute_BrokenUnrelatedProfileDoesNotFailCommand(t *testing.T) {
	profiles := map[string]string{
		"good":   "[container]\nimage = \"good-image\"\n",
		"broken": brokenProfile,
	}
	if err := executeWithProfiles(t, profiles, "", "version", "--profile", "good"); err != nil {
		t.Fatalf("coi version --profile good: %v", err)
	}
	if app.cfg.Container.Image != "good-image" {
		t.Errorf("profile good not applied, image = %q", app.cfg.Container.Image)
	}
	if _, ok := app.cfg.Profiles["broken"]; ok {
		t.Error("the unrelated profile was read")
	}
}

func TestExecute_AllProfilesCommandFailsOnBrokenProfile(t *testing.T) {
	profiles := map[string]string{"broken": brokenProfile}
	err := executeWithProfiles(t, profiles, "", "profile", "list")
	if err == nil || !strings.Contains(err.Error(), "failed to load config:") {
		t.Fatalf("coi profile list = %v, want a config load error", err)
	}
}

// An invalid requested profile fails at config load. An invalid [defaults]
// profile fails the same way in the commands that apply it.
func TestExecute_InvalidRequestedProfileFailsConfigLoad(t *testing.T) {
	tests := map[string]struct {
		userConfig string
		args       []string
	}{
		"--profile":                    {"", []string{"version", "--profile", "broken"}},
		"broken parent":                {"", []string{"version", "--profile", "child"}},
		"[defaults] profile, run":      {"[defaults]\nprofile = \"broken\"\n", []string{"run", "true"}},
		"[defaults] inherits, run":     {"[defaults]\nprofile = \"child\"\n", []string{"run", "true"}},
		"[defaults] profile, attach":   {"[defaults]\nprofile = \"broken\"\n", []string{"attach"}},
		"[defaults] profile, snapshot": {"[defaults]\nprofile = \"broken\"\n", []string{"snapshot", "list"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			profiles := map[string]string{
				"broken": brokenProfile,
				"child":  "inherits = \"broken\"\n",
			}
			err := executeWithProfiles(t, profiles, tt.userConfig, tt.args...)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.HasPrefix(err.Error(), "failed to load config: invalid configuration: ") ||
				!strings.Contains(err.Error(), "failed to parse profile \"broken\"") {
				t.Errorf("unexpected error: %v", err)
			}
			if got := ExitCodeFor(err); got != ExitConfig {
				t.Errorf("exit code = %d, want %d", got, ExitConfig)
			}
		})
	}
}

// A [defaults] profile, unknown or broken, does not fail commands that never
// apply it (#607), and they read no profile.
func TestExecute_DefaultsProfileNotReadByOtherCommands(t *testing.T) {
	for name, defaults := range map[string]string{"unknown": "nope", "broken": "broken"} {
		t.Run(name, func(t *testing.T) {
			profiles := map[string]string{"broken": brokenProfile}
			userConfig := "[defaults]\nprofile = \"" + defaults + "\"\n"
			if err := executeWithProfiles(t, profiles, userConfig, "version"); err != nil {
				t.Fatalf("coi version: %v", err)
			}
			for name := range app.cfg.Profiles {
				if !config.IsBuiltinProfile(name) {
					t.Errorf("profile %q was read", name)
				}
			}
		})
	}
}

func TestExecute_MissingRequestedProfileFails(t *testing.T) {
	err := executeWithProfiles(t, nil, "", "version", "--profile", "gone")
	if err == nil || err.Error() != "profile 'gone' not found" {
		t.Fatalf("coi version --profile gone = %v", err)
	}
}
