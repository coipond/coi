package cli

import (
	"fmt"
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
	return executeArgs(t, args...)
}

// executeArgs runs `coi <args>` with output discarded.
func executeArgs(t *testing.T, args ...string) error {
	t.Helper()
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

// fakeIncusLog puts an `incus` on PATH that logs its calls, one per line, and
// returns the log path.
func fakeIncusLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\ncase \"$*\" in *list*) echo c1 ;; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func TestLoadsNoProfile(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"container", "exec"}, true},
		{[]string{"container", "exists"}, true},
		{[]string{"container", "running"}, true},
		{[]string{"container", "stop"}, true},
		{[]string{"container", "delete"}, true},
		{[]string{"container", "list"}, true},
		{[]string{"container", "info"}, true},
		{[]string{"container", "mount"}, true},
		{[]string{"file", "push"}, true},
		{[]string{"file", "pull"}, true},
		{[]string{"kill"}, true},
		{[]string{"container", "launch"}, false},
		{[]string{"container", "start"}, false},
		{[]string{"shell"}, false},
		{[]string{"run"}, false},
		{[]string{"attach"}, false},
		{[]string{"monitor"}, false},
		{[]string{"snapshot", "list"}, false},
		{[]string{"list"}, false},
	}
	for _, tt := range tests {
		cmd, _, err := rootCmd.Find(tt.args)
		if err != nil {
			t.Fatalf("Find(%v): %v", tt.args, err)
		}
		if got := loadsNoProfile(cmd); got != tt.want {
			t.Errorf("loadsNoProfile(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
	for path := range noProfileCommands {
		cmd, _, err := rootCmd.Find(strings.Fields(path)[1:])
		if err != nil || cmd.CommandPath() != path {
			t.Errorf("noProfileCommands names %q, which is no command", path)
		}
	}
}

// A profile name in two locations still fails these commands (exit 5).
func TestExecute_NoProfileCommandFailsOnDuplicateProfile(t *testing.T) {
	fakeIncusLog(t)
	home, work := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("COI_CONFIG", "")
	t.Chdir(work)
	for _, parent := range []string{home, work} {
		dir := filepath.Join(parent, ".coi", "profiles", "dup")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[container]\nimage = \"a\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := executeArgs(t, "container", "exists", "c1")
	if err == nil || !strings.Contains(err.Error(), `profile "dup" defined in multiple locations`) {
		t.Fatalf("coi container exists = %v, want a duplicate profile error", err)
	}
	if got := ExitCodeFor(err); got != ExitConfig {
		t.Errorf("exit code = %d, want %d", got, ExitConfig)
	}
}

// Container-level commands list no profile, so they cost the same with
// thousands of profiles, and issue exactly one incus call.
func TestExecute_NoProfileCommandsReadNoProfile(t *testing.T) {
	profiles := map[string]string{"broken": brokenProfile}
	for i := range 3000 {
		profiles[fmt.Sprintf("p%d", i)] = "[container]\nimage = \"img\"\n"
	}
	src := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(src, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]string{
		"container exists":     {"container", "exists", "c1"},
		"container exec --cwd": {"container", "exec", "c1", "--cwd", "/", "--", "true"},
		"file push":            {"file", "push", src, "c1:/tmp/f.txt"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			logPath := fakeIncusLog(t)
			userConfig := "[defaults]\nprofile = \"p1\"\n"
			if err := executeWithProfiles(t, profiles, userConfig, args...); err != nil {
				t.Fatalf("coi %v: %v", args, err)
			}
			if p := app.cfg.GetProfile("p1"); p != nil {
				t.Error("a profile was listed")
			}
			b, _ := os.ReadFile(logPath)
			if calls := strings.Split(strings.TrimSpace(string(b)), "\n"); len(calls) != 1 {
				t.Errorf("incus calls = %q, want one", calls)
			}
		})
	}
}

func TestExecute_NoProfileCommandAppliesRequestedProfile(t *testing.T) {
	fakeIncusLog(t)
	profiles := map[string]string{"good": "[incus]\nproject = \"good-project\"\n"}
	if err := executeWithProfiles(t, profiles, "", "container", "exists", "c1", "--profile", "good"); err != nil {
		t.Fatalf("coi container exists --profile good: %v", err)
	}
	if app.cfg.Incus.Project != "good-project" {
		t.Errorf("profile good not applied, project = %q", app.cfg.Incus.Project)
	}
}
