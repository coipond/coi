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
	eager, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for name := range builtinProfiles {
		got, ok := cfg.Profiles[name]
		if !ok {
			t.Fatalf("built-in name %q not loaded at load", name)
		}
		if !reflect.DeepEqual(got, eager.Profiles[name]) {
			t.Errorf("%s differs from Load's:\n got  %+v\n want %+v", name, got, eager.Profiles[name])
		}
	}
	if cfg.Profiles["default"].Container.Image != "disk-default" {
		t.Errorf("disk default profile not used: %+v", cfg.Profiles["default"])
	}
}

// LoadOnDemand reads one profile, so its time must not grow with the number
// of profiles on disk:
//
//	go test ./internal/config -run '^$' -bench LoadProfiles -benchtime 20x
func BenchmarkLoadProfiles(b *testing.B) {
	for _, count := range []int{10, 1000, 5000} {
		coiDir := onDemandHome(b)
		for i := range count {
			writeTestProfile(b, coiDir, fmt.Sprintf("slot-%05d", i),
				"[container]\nimage = \"coi-default\"\npersistent = true\n[environment]\nNODE = \"n1\"\n")
		}
		b.Run(fmt.Sprintf("on-demand/%d", count), func(b *testing.B) {
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
