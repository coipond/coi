package session

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// fakeDirsManager is a fakeCodexSetupManager whose PushFile fails, as
// `incus file push` does, when the destination's parent dir does not exist.
// mkdir -p via ExecArgs creates dirs; every ExecArgs call is recorded.
type fakeDirsManager struct {
	*fakeCodexSetupManager
	dirs     map[string]bool
	execArgs [][]string
}

func newFakeDirsManager(existing ...string) *fakeDirsManager {
	f := &fakeDirsManager{fakeCodexSetupManager: newFakeCodexSetupManager(), dirs: map[string]bool{}}
	for _, d := range existing {
		f.dirs[d] = true
	}
	return f
}

func (f *fakeDirsManager) ExecArgs(args []string, _ container.ExecCommandOptions) error {
	f.execArgs = append(f.execArgs, args)
	if len(args) == 3 && args[0] == "mkdir" && args[1] == "-p" {
		f.dirs[args[2]] = true
	}
	return nil
}

func (f *fakeDirsManager) PushFile(src, dest string) error {
	if !f.dirs[filepath.Dir(dest)] {
		return fmt.Errorf("no such directory: %s", filepath.Dir(dest))
	}
	return f.fakeAutoCtxManager.PushFile(src, dest)
}

func configDirFilesTool(t *testing.T, name string) tool.ToolWithConfigDirFiles {
	t.Helper()
	tl, err := tool.Get(name)
	if err != nil {
		t.Fatalf("Get(%s): %v", name, err)
	}
	tcf, ok := tl.(tool.ToolWithConfigDirFiles)
	if !ok {
		t.Fatalf("%s must implement ToolWithConfigDirFiles", name)
	}
	return tcf
}

// TestInjectCredentials_Goose_CreatesTokenSubdir: on resume, a host token in a
// subdir the saved session lacks (the user signed in after the last session)
// is pushed, not skipped.
func TestInjectCredentials_Goose_CreatesTokenSubdir(t *testing.T) {
	hostDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hostDir, "chatgpt_codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	const token = `{"access_token": "fresh"}`
	if err := os.WriteFile(filepath.Join(hostDir, "chatgpt_codex", "tokens.json"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "config.yaml"), []byte("GOOSE_PROVIDER: openai\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	mgr := newFakeDirsManager("/home/code/.config/goose")
	copied, err := injectCredentials(mgr, hostDir, "/home/code", configDirFilesTool(t, "goose"), func(string) {})
	if err != nil {
		t.Fatalf("injectCredentials failed: %v", err)
	}

	if got := mgr.files["/home/code/.config/goose/chatgpt_codex/tokens.json"]; got != token {
		t.Errorf("chatgpt_codex/tokens.json not refreshed on resume: %q", got)
	}
	if len(copied) != 2 {
		t.Errorf("copied = %+v, want config.yaml and chatgpt_codex/tokens.json", copied)
	}
}

// TestInjectCredentials_TopLevelFiles_NoMkdir: tools whose files all sit in
// the config dir itself run no extra command on resume.
func TestInjectCredentials_TopLevelFiles_NoMkdir(t *testing.T) {
	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "auth.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	mgr := newFakeDirsManager("/home/code/.codex")
	if _, err := injectCredentials(mgr, hostDir, "/home/code", configDirFilesTool(t, "codex"), func(string) {}); err != nil {
		t.Fatalf("injectCredentials failed: %v", err)
	}
	if len(mgr.execArgs) != 0 {
		t.Errorf("ExecArgs calls = %v, want none", mgr.execArgs)
	}
	if _, ok := mgr.files["/home/code/.codex/auth.json"]; !ok {
		t.Error("auth.json not refreshed on resume")
	}
}
