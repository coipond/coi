package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
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
	if !strings.Contains(string(b), "config set coi-aaaaaaaa-1 ephemeral=false --property") {
		t.Errorf("want the Incus ephemeral property cleared; calls:\n%s", b)
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

// fakeSlotIncus puts an `incus` on PATH whose `incus list` prints rows
// ("name,STATUS,user.coi.persistent" lines) and whose `config get` of a
// container answers its third column.
func fakeSlotIncus(t *testing.T, rows string) {
	t.Helper()
	dir := t.TempDir()
	rowsPath := filepath.Join(dir, "rows")
	if err := os.WriteFile(rowsPath, []byte(rows), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$*\" in\n" +
		"  *\" list \"*) cat " + rowsPath + " ;;\n" +
		"  *\" config get \"*) grep \"^$5,\" " + rowsPath + " | cut -d, -f3 ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Each slot source of `coi shell` and `coi run` inherits a stopped container
// marked persistent; an explicit [container] persistent = false wins.
func TestChooseSlot_InheritsMarkedContainer(t *testing.T) {
	t.Setenv("COI_CONTAINER_PREFIX", "")
	workspace := "/home/u/slots"
	slot1 := session.ContainerName(workspace, "", 1)
	no := false
	for _, tt := range []struct {
		name           string
		run            bool
		slot, resume   int
		cfg            *bool
		rows           string
		want           int
		wantPersistent bool
	}{
		{name: "shell auto", rows: slot1 + ",STOPPED,true\n", want: 1, wantPersistent: true},
		{name: "shell auto, explicit false", cfg: &no, rows: slot1 + ",STOPPED,true\n", want: 2},
		{name: "shell auto, not marked", rows: slot1 + ",STOPPED,false\n", want: 2},
		{name: "shell --slot", slot: 1, rows: slot1 + ",STOPPED,true\n", want: 1, wantPersistent: true},
		{name: "shell --slot, not marked", slot: 1, rows: slot1 + ",STOPPED,false\n", want: 1},
		{name: "shell resume slot", resume: 1, rows: slot1 + ",STOPPED,true\n", want: 1, wantPersistent: true},
		{name: "run auto", run: true, rows: slot1 + ",STOPPED,true\n", want: 1, wantPersistent: true},
		{name: "run auto, explicit false", run: true, cfg: &no, rows: slot1 + ",STOPPED,true\n", want: 2},
		{name: "run --slot", run: true, slot: 1, rows: slot1 + ",STOPPED,true\n", want: 1, wantPersistent: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fakeSlotIncus(t, tt.rows)
			a := &App{cfg: &config.Config{}, slot: tt.slot}
			a.cfg.Container.Persistent = tt.cfg
			var got int
			var err error
			if tt.run {
				got, err = a.chooseRunSlot(workspace)
			} else {
				got, err = a.chooseShellSlot(workspace, tt.resume)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want || a.persistent != tt.wantPersistent {
				t.Errorf("slot %d, persistent %v; want %d, %v", got, a.persistent, tt.want, tt.wantPersistent)
			}
		})
	}
}

// endRunManager records how the run teardown ends the container.
type endRunManager struct {
	container.ContainerManager
	deleted, stopped bool
}

func (m *endRunManager) Delete(bool) error      { m.deleted = true; return nil }
func (m *endRunManager) Stop(bool) error        { m.stopped = true; return nil }
func (m *endRunManager) Running() (bool, error) { return true, nil }

// The run teardown keeps a container `coi persist` marked during the run.
func TestEndRunContainer(t *testing.T) {
	for _, tt := range []struct {
		name       string
		persistent bool
		key        string
		wantDelete bool
	}{
		{name: "ephemeral run", key: "false", wantDelete: true},
		{name: "persisted during the run", key: "true"},
		{name: "persistent run", persistent: true, key: "true"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fakeSlotIncus(t, "coi-run-1,RUNNING,"+tt.key+"\n")
			mgr := &endRunManager{}
			a := &App{cfg: &config.Config{}, persistent: tt.persistent}
			a.endRunContainer(mgr, "coi-run-1")
			if mgr.deleted != tt.wantDelete || mgr.stopped == tt.wantDelete {
				t.Errorf("deleted %v, stopped %v; want deleted %v", mgr.deleted, mgr.stopped, tt.wantDelete)
			}
		})
	}
}
