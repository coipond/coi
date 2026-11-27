package container

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runTmpCleanupScript runs the SetTmpCleanup script with its files moved into
// dir and returns the env file and the tmpfiles.d rule it wrote.
func runTmpCleanupScript(t *testing.T, dir, maxSize, maxAge string) (env, conf string) {
	t.Helper()
	script, err := tmpCleanupScript(maxSize, maxAge)
	if err != nil {
		t.Fatalf("tmpCleanupScript(%q, %q): %v", maxSize, maxAge, err)
	}
	envPath, confPath := filepath.Join(dir, "env"), filepath.Join(dir, "conf")
	script = strings.ReplaceAll(script, tmpCleanupEnvPath, envPath)
	script = strings.ReplaceAll(script, tmpCleanupConfPath, confPath)
	if out, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	e, _ := os.ReadFile(envPath)
	c, _ := os.ReadFile(confPath)
	return string(e), string(c)
}

func TestTmpCleanupScript(t *testing.T) {
	tests := []struct {
		maxSize, maxAge string
		env, rule       string
	}{
		{"", "", "TMP_MAX_BYTES=4294967296\n", "D /tmp 1777 root root 7d\n"},
		{"512MiB", "12h", "TMP_MAX_BYTES=536870912\n", "D /tmp 1777 root root 12h\n"},
		{"0", "0", "TMP_MAX_BYTES=0\n", "D /tmp 1777 root root -\n"},
		{"2G", "30min", "TMP_MAX_BYTES=2147483648\n", "D /tmp 1777 root root 30min\n"},
	}
	for _, tt := range tests {
		env, conf := runTmpCleanupScript(t, t.TempDir(), tt.maxSize, tt.maxAge)
		if env != tt.env {
			t.Errorf("(%q, %q) env = %q, want %q", tt.maxSize, tt.maxAge, env, tt.env)
		}
		if !strings.HasSuffix(conf, "\n"+tt.rule) {
			t.Errorf("(%q, %q) tmpfiles.d rule = %q, want it to end with %q", tt.maxSize, tt.maxAge, conf, tt.rule)
		}
	}
}

func TestTmpCleanupScriptInvalid(t *testing.T) {
	for _, tt := range []struct{ maxSize, maxAge string }{
		{"lots", "7d"},
		{"-1", "7d"},
		{"4GiB", "7 days"},
		{"4GiB", "1.5d"},
		{"4GiB", "-1d"},
		{"4GiB", "7d; rm -rf /"},
	} {
		if _, err := tmpCleanupScript(tt.maxSize, tt.maxAge); err == nil {
			t.Errorf("tmpCleanupScript(%q, %q) succeeded, want error", tt.maxSize, tt.maxAge)
		}
	}
}
