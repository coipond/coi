package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func runWorkspaceKeyApp(persistent bool) *App {
	cfg := config.GetDefaultConfig()
	cfg.Network.Mode = config.NetworkModeOpen
	cfg.Security.DisableProtection = true
	cfg.Limits = config.LimitsConfig{}
	return &App{cfg: cfg, persistent: persistent}
}

func TestLaunchContainerRunPhase_FreshLaunchRecordsWorkspace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	// An incus that knows no container: the phase creates a fresh one.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte("#!/bin/sh\necho \"$*\" >> "+logPath+"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &runState{absWorkspace: ws, containerName: "run-wsfresh", img: "coi-default", slot: 1}

	if _, err := runWorkspaceKeyApp(false).launchContainerRunPhase(s).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "init coi-default run-wsfresh --ephemeral -c user.coi.managed=true -c user.coi.workspace="+ws+" -c user.coi.persistent=false -c ") {
		t.Errorf("want the workspace key on incus init; calls:\n%s", b)
	}
}

func TestLaunchContainerRunPhase_RestartRecordsWorkspace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	// A persistent container from an older coi: no workspace key.
	logPath := fakeStoppedIncus(t, "run-wsrestart",
		"config: {}\ndevices:\n  workspace:\n    path: /workspace\n    source: "+ws+"\n    type: disk\n")
	s := &runState{absWorkspace: ws, containerName: "run-wsrestart", img: "coi-default", slot: 1}

	if _, err := runWorkspaceKeyApp(true).launchContainerRunPhase(s).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath)
	log := string(b)
	start := strings.Index(log, "start run-wsrestart")
	for _, kv := range []string{"user.coi.workspace=" + ws, "user.coi.persistent=true"} {
		set := strings.Index(log, "config set run-wsrestart "+kv)
		if set < 0 || start < 0 || set > start {
			t.Errorf("want %s set before the start; calls:\n%s", kv, log)
		}
	}
}
