package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// loadOnDemandWithProfiles writes ~/.coi/profiles/<name>/config.toml files
// under a temp HOME and loads the config as `coi shell` does.
func loadOnDemandWithProfiles(t *testing.T, userConfig string, profiles map[string]string) *config.Config {
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
	if err := os.MkdirAll(filepath.Join(home, ".coi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".coi", "config.toml"), []byte(userConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadOnDemand()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

type pruneCall struct {
	dir   string
	bases []string
}

func stubPruneUbuntuCache(t *testing.T) *[]pruneCall {
	t.Helper()
	var calls []pruneCall
	orig := pruneUbuntuCacheFn
	pruneUbuntuCacheFn = func(dir string, bases []string, _ func(string)) {
		calls = append(calls, pruneCall{dir, bases})
	}
	t.Cleanup(func() { pruneUbuntuCacheFn = orig })
	return &calls
}

func TestConfiguredBasesReadsPendingProfiles(t *testing.T) {
	cfg := loadOnDemandWithProfiles(t, "[container.build]\nbase = \"ubuntu:22.04\"\n", map[string]string{
		"old":    "[container.build]\nbase = \"ubuntu:24.04\"\n",
		"plain":  "[container]\nimage = \"plain\"\n",
		"broken": brokenProfile,
	})

	got := configuredBases(cfg)
	want := []string{"ubuntu:22.04", "ubuntu:24.04"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRecordBuildPrunesWithConfiguredBases(t *testing.T) {
	cfg := loadOnDemandWithProfiles(t, "", map[string]string{
		"old": "[container.build]\nbase = \"ubuntu:24.04\"\n",
	})
	calls := stubPruneUbuntuCache(t)

	recordBuild(cfg, "coi-default", "ubuntu:26.04")

	dir, err := coiDataDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "image-meta.json")); err != nil {
		t.Errorf("build not recorded: %v", err)
	}
	want := []pruneCall{{dir, []string{"ubuntu:24.04"}}}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("got prune calls %+v, want %+v", *calls, want)
	}
}

func TestPruneAfterBuildAll(t *testing.T) {
	cfg := loadOnDemandWithProfiles(t, "", nil)
	calls := stubPruneUbuntuCache(t)

	pruneAfterBuildAll(cfg, 0)
	if len(*calls) != 0 {
		t.Fatalf("pruned with nothing built: %+v", *calls)
	}
	pruneAfterBuildAll(cfg, 2)
	if len(*calls) != 1 {
		t.Errorf("want one prune after builds, got %+v", *calls)
	}
}
