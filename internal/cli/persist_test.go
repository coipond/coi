package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/session"
)

func TestPersistCommand_SetsPersistentKey(t *testing.T) {
	sessionsDir := useTopHome(t)
	writeSavedSession(t, sessionsDir, "s1", "coi-aaaaaaaa-1", "/home/u/proj", false)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\ncase \"$*\" in\n  *\"list \"*) echo coi-aaaaaaaa-1 ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

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
