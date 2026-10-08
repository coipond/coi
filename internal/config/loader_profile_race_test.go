package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

const raceProfileContent = "[container]\npersistent = true\n"

// writeProfileAtomically creates <profiles>/<name>/config.toml the way a well-behaved writer
// does (temp file + rename), so the scan only ever sees a complete file or none.
func writeProfileAtomically(t *testing.T, profilesDir, name string) {
	t.Helper()
	dir := filepath.Join(profilesDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Error(err)
		return
	}
	tmp := filepath.Join(dir, ".config.toml.tmp")
	if err := os.WriteFile(tmp, []byte(raceProfileContent), 0o644); err != nil {
		t.Error(err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, "config.toml")); err != nil {
		t.Error(err)
	}
}

// Another process (an orchestrator launching many sessions) creates and deletes its own
// profiles while this one scans the directory. A profile removed mid-scan must be skipped, not
// fail the command: every coi command loads every profile, so the failure used to hit
// unrelated sessions at random.
func TestLoadProfileDirectories_ProfileRemovedMidScan(t *testing.T) {
	configDir := t.TempDir()
	profilesDir := filepath.Join(configDir, "profiles")
	writeProfileAtomically(t, profilesDir, "mine")
	for i := range 20 {
		writeProfileAtomically(t, profilesDir, fmt.Sprintf("other-%02d", i))
	}

	var stop atomic.Bool
	var churn sync.WaitGroup
	churn.Go(func() {
		for i := 0; !stop.Load(); i++ {
			name := fmt.Sprintf("other-%02d", i%20)
			_ = os.RemoveAll(filepath.Join(profilesDir, name))
			writeProfileAtomically(t, profilesDir, name)
		}
	})

	var firstErr error
	for range 300 {
		cfg := GetDefaultConfig()
		if err := loadProfileDirectories(cfg, configDir, true); err != nil {
			firstErr = err
			break
		}
		if _, ok := cfg.Profiles["mine"]; !ok {
			firstErr = fmt.Errorf("the stable profile was not loaded")
			break
		}
	}
	stop.Store(true)
	churn.Wait()

	if firstErr != nil {
		t.Fatalf("scan failed while other profiles were being removed: %v", firstErr)
	}
}
