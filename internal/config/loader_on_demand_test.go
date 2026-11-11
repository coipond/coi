package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeTestProfile writes <parent>/profiles/<name>/config.toml.
func writeTestProfile(t testing.TB, parent, name, content string) string {
	t.Helper()
	dir := filepath.Join(parent, "profiles", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// onDemandHome sets a temp HOME and CWD and returns HOME/.coi.
func onDemandHome(t testing.TB) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("COI_CONFIG", "")
	t.Chdir(t.TempDir())
	return filepath.Join(home, ".coi")
}

func TestLoadOnDemand_BrokenUnrelatedProfileNotRead(t *testing.T) {
	coiDir := onDemandHome(t)
	writeTestProfile(t, coiDir, "good", "[container]\nimage = \"good-image\"\n")
	brokenPath := writeTestProfile(t, coiDir, "broken", "[container\nimage = \n")

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatalf("LoadOnDemand() failed on an unrelated broken profile: %v", err)
	}
	if _, ok := cfg.Profiles["broken"]; ok {
		t.Error("the unrelated profile was read")
	}
	if err := cfg.ApplyProfile("good"); err != nil {
		t.Fatalf("ApplyProfile(good): %v", err)
	}
	if cfg.Container.Image != "good-image" {
		t.Errorf("image = %q, want good-image", cfg.Container.Image)
	}

	_, lookupErr := cfg.LookupProfile("broken")
	var cfgErr *ConfigError
	if !errors.As(lookupErr, &cfgErr) {
		t.Fatalf("LookupProfile(broken) = %v, want a *ConfigError", lookupErr)
	}
	_, loadErr := Load()
	if loadErr == nil {
		t.Fatal("Load() must still fail on the broken profile")
	}
	if lookupErr.Error() != loadErr.Error() {
		t.Errorf("errors differ:\n LookupProfile: %v\n Load:          %v", lookupErr, loadErr)
	}
	if !strings.Contains(lookupErr.Error(), brokenPath) {
		t.Errorf("error should name %s, got: %v", brokenPath, lookupErr)
	}
	if err := cfg.ApplyProfile("broken"); err == nil || err.Error() != lookupErr.Error() {
		t.Errorf("second ApplyProfile(broken) = %v, want %v", err, lookupErr)
	}
}

func TestLoadOnDemand_MissingProfile(t *testing.T) {
	coiDir := onDemandHome(t)
	writeTestProfile(t, coiDir, "good", "[container]\nimage = \"good-image\"\n")

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	eager, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got, want := cfg.ApplyProfile("nope"), eager.ApplyProfile("nope")
	if got == nil || want == nil || got.Error() != want.Error() {
		t.Errorf("ApplyProfile(nope) = %v, want %v", got, want)
	}
}

func TestLoadOnDemand_ResolvesInheritance(t *testing.T) {
	coiDir := onDemandHome(t)
	writeTestProfile(t, coiDir, "base",
		"inherits = \"hardened\"\n[container]\nimage = \"base-image\"\n[environment]\nFROM_BASE = \"1\"\n")
	writeTestProfile(t, coiDir, "child",
		"inherits = \"base\"\n[environment]\nFROM_CHILD = \"1\"\n")
	writeTestProfile(t, coiDir, "other", "[container]\nimage = \"other\"\n")

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	eager, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	got, err := cfg.LookupProfile("child")
	if err != nil || got == nil {
		t.Fatalf("LookupProfile(child) = %v, %v", got, err)
	}
	want := eager.GetProfile("child")
	if !reflect.DeepEqual(*got, *want) {
		t.Errorf("on-demand child differs from Load's:\n got  %+v\n want %+v", *got, *want)
	}
	if got.Container.Image != "base-image" || got.Environment["FROM_BASE"] != "1" || got.Environment["FROM_CHILD"] != "1" {
		t.Errorf("child not resolved through base: %+v", *got)
	}
	if _, ok := cfg.Profiles["other"]; ok {
		t.Error("a profile outside the chain was read")
	}
	if base := cfg.GetProfile("base"); base == nil || !reflect.DeepEqual(*base, *eager.GetProfile("base")) {
		t.Errorf("base after child = %+v, want %+v", base, eager.GetProfile("base"))
	}
}

func TestLoadOnDemand_InheritanceErrors(t *testing.T) {
	tests := map[string]map[string]string{
		"missing parent": {"child": "inherits = \"gone\"\n"},
		"cycle":          {"child": "inherits = \"a\"\n", "a": "inherits = \"b\"\n", "b": "inherits = \"a\"\n"},
		"broken parent":  {"child": "inherits = \"a\"\n", "a": "[container\n"},
	}
	for name, profiles := range tests {
		t.Run(name, func(t *testing.T) {
			coiDir := onDemandHome(t)
			for n, content := range profiles {
				writeTestProfile(t, coiDir, n, content)
			}
			cfg, err := LoadOnDemand()
			if err != nil {
				t.Fatal(err)
			}
			_, loadErr := Load()
			if loadErr == nil {
				t.Fatal("Load() should fail")
			}
			_, err = cfg.LookupProfile("child")
			if err == nil {
				t.Fatal("LookupProfile(child) should fail")
			}
			if name != "cycle" && err.Error() != loadErr.Error() {
				t.Errorf("errors differ:\n LookupProfile: %v\n Load:          %v", err, loadErr)
			}
			if p := cfg.GetProfile("child"); p != nil {
				t.Errorf("a failed profile must not be returned, got %+v", *p)
			}
		})
	}
}

func TestLoadOnDemand_DuplicateAcrossLocations(t *testing.T) {
	coiDir := onDemandHome(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	homePath := writeTestProfile(t, coiDir, "dup", "[container]\nimage = \"home\"\n")
	projPath := writeTestProfile(t, filepath.Join(cwd, ".coi"), "dup", "[container]\nimage = \"project\"\n")

	_, err = LoadOnDemand()
	if err == nil {
		t.Fatal("LoadOnDemand() should fail on a name in two locations")
	}
	if !strings.Contains(err.Error(), "multiple locations") ||
		!strings.Contains(err.Error(), homePath) || !strings.Contains(err.Error(), projPath) {
		t.Errorf("unexpected error: %v", err)
	}
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Errorf("want a *ConfigError, got %T", err)
	}

	if err := os.Remove(homePath); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatalf("LoadOnDemand() with an empty home dir: %v", err)
	}
	if p := cfg.GetProfile("dup"); p == nil || p.Container.Image != "project" {
		t.Errorf("dup = %+v, want the project profile", p)
	}

	// A project directory without config.toml does not clash with a home one.
	writeTestProfile(t, coiDir, "dup", "[container]\nimage = \"home\"\n")
	if err := os.Remove(projPath); err != nil {
		t.Fatal(err)
	}
	for name, load := range map[string]func() (*Config, error){"LoadOnDemand": LoadOnDemand, "Load": Load} {
		cfg, err := load()
		if err != nil {
			t.Fatalf("%s() with an empty project dir: %v", name, err)
		}
		if p := cfg.GetProfile("dup"); p == nil || p.Container.Image != "home" {
			t.Errorf("%s: dup = %+v, want the home profile", name, p)
		}
	}
}

func TestLoadOnDemand_ProfileRemovedAfterListing(t *testing.T) {
	coiDir := onDemandHome(t)
	path := writeTestProfile(t, coiDir, "gone", "[container]\nimage = \"x\"\n")

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	p, err := cfg.LookupProfile("gone")
	if p != nil || err != nil {
		t.Errorf("LookupProfile(gone) = %v, %v; want nil, nil", p, err)
	}
	if err := cfg.ApplyProfile("gone"); err == nil || err.Error() != "profile 'gone' not found" {
		t.Errorf("ApplyProfile(gone) = %v", err)
	}
}

func TestLoadOnDemand_DiskProfileOverridesBuiltin(t *testing.T) {
	coiDir := onDemandHome(t)
	writeTestProfile(t, coiDir, "default", "inherits = \"hardened\"\n[container]\nimage = \"disk-default\"\n")

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Profiles["default"]; ok {
		t.Error("the disk default profile was read at load")
	}
	eager, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for name := range builtinProfiles {
		got := cfg.GetProfile(name)
		if got == nil {
			t.Fatalf("built-in name %q not found", name)
		}
		if !reflect.DeepEqual(*got, eager.Profiles[name]) {
			t.Errorf("%s differs from Load's:\n got  %+v\n want %+v", name, *got, eager.Profiles[name])
		}
	}
	if cfg.Profiles["default"].Container.Image != "disk-default" {
		t.Errorf("disk default profile not used: %+v", cfg.Profiles["default"])
	}
}

// A disk profile named like a built-in that is removed before it is read
// leaves the built-in, as Load does.
func TestLoadOnDemand_RemovedDiskBuiltinFallsBack(t *testing.T) {
	coiDir := onDemandHome(t)
	path := writeTestProfile(t, coiDir, "default", "[container]\nimage = \"disk-default\"\n")

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	eager, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.GetProfile("default")
	if got == nil || !reflect.DeepEqual(*got, eager.Profiles["default"]) {
		t.Errorf("default = %+v, want the built-in %+v", got, eager.Profiles["default"])
	}
}

// With thousands of profiles on disk, a command that uses no profile reads
// none, and one that applies a profile reads only that one.
func TestLoadOnDemand_ReadsOnlyUsedProfiles(t *testing.T) {
	coiDir := onDemandHome(t)
	writeTestProfile(t, coiDir, "base", "[environment]\nBASE = \"1\"\n")
	for i := range 3000 {
		writeTestProfile(t, coiDir, fmt.Sprintf("slot-%05d", i), "inherits = \"base\"\n")
	}

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Profiles); got != len(builtinProfiles) {
		t.Errorf("profiles read at load = %d, want only the %d built-ins", got, len(builtinProfiles))
	}
	if err := cfg.ApplyProfile("slot-00042"); err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Profiles); got != len(builtinProfiles)+2 {
		t.Errorf("profiles read after ApplyProfile = %d, want the built-ins, slot-00042 and base", got)
	}
}

// LoadOnDemand reads no profile for a command that uses none (coi container
// list) and one for a command that applies one (coi shell --profile X), so its
// time grows only with the directory listing, not with reading every profile:
//
//	go test ./internal/config -run '^$' -bench LoadProfiles -benchtime 20x
func BenchmarkLoadProfiles(b *testing.B) {
	for _, count := range []int{10, 1000, 5000} {
		coiDir := onDemandHome(b)
		for i := range count {
			writeTestProfile(b, coiDir, fmt.Sprintf("slot-%05d", i),
				"[container]\nimage = \"coi-default\"\npersistent = true\n[environment]\nNODE = \"n1\"\n")
		}
		b.Run(fmt.Sprintf("no-profile/%d", count), func(b *testing.B) {
			for b.Loop() {
				if _, err := LoadOnDemand(); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("one-profile/%d", count), func(b *testing.B) {
			for b.Loop() {
				cfg, err := LoadOnDemand()
				if err != nil {
					b.Fatal(err)
				}
				if err := cfg.ApplyProfile("slot-00001"); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("all/%d", count), func(b *testing.B) {
			for b.Loop() {
				if _, err := Load(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// A project profile must not get a trusted parent's session_name through
// inheritance, and an invalid inherited session_name fails the lookup.
func TestLoadOnDemand_InheritedSessionName(t *testing.T) {
	coiDir := onDemandHome(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	writeTestProfile(t, coiDir, "trusted", "[container]\nsession_name = \"mine\"\n")
	writeTestProfile(t, filepath.Join(cwd, ".coi"), "project", "inherits = \"trusted\"\n")

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	p, err := cfg.LookupProfile("project")
	if err != nil || p == nil {
		t.Fatalf("LookupProfile(project) = %v, %v", p, err)
	}
	if p.Container.SessionName != "" {
		t.Errorf("project profile kept the inherited session_name %q", p.Container.SessionName)
	}
	if p := cfg.GetProfile("trusted"); p == nil || p.Container.SessionName != "mine" {
		t.Errorf("trusted profile lost its session_name: %+v", p)
	}
}

func TestLoadOnDemand_InvalidSessionNameFails(t *testing.T) {
	coiDir := onDemandHome(t)
	writeTestProfile(t, coiDir, "base", "[container]\nimage = \"x\"\n")
	writeTestProfile(t, coiDir, "child", "inherits = \"base\"\n")

	cfg, err := LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	// The schema rejects a bad session_name on disk, so set one on the loaded
	// parent, as a merge of other sources could.
	if _, err := cfg.LookupProfile("base"); err != nil {
		t.Fatal(err)
	}
	base := cfg.Profiles["base"]
	base.Container.SessionName = "bad name"
	cfg.Profiles["base"] = base

	_, err = cfg.LookupProfile("child")
	if err == nil || !strings.Contains(err.Error(), `profile "child"`) {
		t.Fatalf("LookupProfile(child) = %v, want a session_name error", err)
	}
	if p := cfg.GetProfile("child"); p != nil {
		t.Errorf("a failed profile must not be returned, got %+v", *p)
	}
}
