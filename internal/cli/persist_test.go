package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/session"
	"github.com/coipond/coi/internal/tool"
)

func TestPersistCommand_SetsPersistentKey(t *testing.T) {
	sessionsDir := useTopHome(t)
	writeSavedSession(t, sessionsDir, "s1", "coi-aaaaaaaa-1", "/home/u/proj", false)
	logPath := fakePersistIncus(t, "coi-aaaaaaaa-1", "")

	if err := persistCommand(persistCmd, []string{"coi-aaaaaaaa-1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "config set coi-aaaaaaaa-1 "+session.PersistentConfigKey+"=true") {
		t.Errorf("want %s=true set on the container; calls:\n%s", session.PersistentConfigKey, b)
	}
	md, err := session.LoadSessionMetadata(filepath.Join(sessionsDir, "s1", "metadata.json"))
	if err != nil || !md.Persistent {
		t.Errorf("metadata persistent = %v (err %v); want true", md.Persistent, err)
	}
}

// fakePersistIncus puts an `incus` on PATH that lists name, answers
// `config get` for the persistent key with key, and logs its calls.
func fakePersistIncus(t *testing.T, name, key string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\ncase \"$*\" in\n" +
		"  *\"config get \"*) echo " + key + " ;;\n" +
		"  *\"list \"*) echo " + name + " ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// A container started with another tool's profile has its metadata in that
// tool's sessions dir.
func TestPersistCommand_FindsOtherToolMetadata(t *testing.T) {
	useTopHome(t)
	codexDir := session.GetSessionsDir(filepath.Join(os.Getenv("HOME"), ".coi"), tool.NewCodex())
	writeSavedSession(t, codexDir, "s1", "coi-bbbbbbbb-1", "/home/u/proj", false)
	logPath := fakePersistIncus(t, "coi-bbbbbbbb-1", "")

	if err := persistCommand(persistCmd, []string{"coi-bbbbbbbb-1"}); err != nil {
		t.Fatal(err)
	}
	md, err := session.LoadSessionMetadata(filepath.Join(codexDir, "s1", "metadata.json"))
	if err != nil || !md.Persistent {
		t.Errorf("codex metadata persistent = %v (err %v); want true", md.Persistent, err)
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "config set coi-bbbbbbbb-1 "+session.PersistentConfigKey+"=true") {
		t.Errorf("want %s=true set on the container; calls:\n%s", session.PersistentConfigKey, b)
	}
}

// Without any session metadata the container key alone is set.
func TestPersistCommand_NoMetadataSetsKey(t *testing.T) {
	useTopHome(t)
	logPath := fakePersistIncus(t, "coi-cccccccc-1", "")

	if err := persistCommand(persistCmd, []string{"coi-cccccccc-1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "config set coi-cccccccc-1 "+session.PersistentConfigKey+"=true") {
		t.Errorf("want %s=true set on the container; calls:\n%s", session.PersistentConfigKey, b)
	}
}

// A launch without [container] persistent in config inherits a key set by
// `coi persist`; an explicit config value wins and skips the read.
func TestInheritPersistedContainer(t *testing.T) {
	no := false
	for _, tt := range []struct {
		name     string
		cfg      *bool
		key      string
		want     bool
		wantRead bool
	}{
		{name: "unset config, marked", key: "true", want: true, wantRead: true},
		{name: "unset config, not marked", key: "false", wantRead: true},
		{name: "explicit false wins", cfg: &no, key: "true"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logPath := fakePersistIncus(t, "coi-dddddddd-1", tt.key)
			a := &App{cfg: &config.Config{}}
			a.cfg.Container.Persistent = tt.cfg
			a.inheritPersistedContainer("coi-dddddddd-1")
			if a.persistent != tt.want {
				t.Errorf("persistent = %v, want %v", a.persistent, tt.want)
			}
			b, _ := os.ReadFile(logPath)
			if read := strings.Contains(string(b), "config get "); read != tt.wantRead {
				t.Errorf("key read = %v, want %v; calls:\n%s", read, tt.wantRead, b)
			}
		})
	}
}
