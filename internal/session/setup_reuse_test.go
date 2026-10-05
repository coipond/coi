package session

import (
	"fmt"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// fakeDirProbe is a minimal containerCommandRunner: it records the command and
// returns success/failure to stand in for the marker-check's exit status.
type fakeDirProbe struct {
	seeded bool
	gotCmd string
}

func (f *fakeDirProbe) ExecCommand(cmd string, _ container.ExecCommandOptions) (string, error) {
	f.gotCmd = cmd
	if f.seeded {
		return "", nil
	}
	return "", fmt.Errorf("exit status 1") // marker absent
}

// toolConfigSeeded must key off the tool's ESSENTIAL config files, not the
// dir's existence or content — the base image pre-creates the config dirs and
// agent installers can leave unrelated files in them, so an existence/content
// check would wrongly report a tool already-configured and skip reuse-seeding
// (#708 follow-up).
func TestToolConfigSeeded(t *testing.T) {
	c, err := tool.Get("claude")
	if err != nil {
		t.Fatalf("tool.Get: %v", err)
	}
	tcf, ok := c.(tool.ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("claude should implement ToolWithConfigDirFiles")
	}

	t.Run("seeded when an essential file exists", func(t *testing.T) {
		fp := &fakeDirProbe{seeded: true}
		if !toolConfigSeeded(fp, "/home/code", tcf) {
			t.Error("want seeded=true when an essential config file exists")
		}
		// It must test the tool's essential files (not `test -d`/`ls -A`, which
		// the pre-created dirs / installer files would fool).
		for _, f := range tcf.EssentialConfigFiles() {
			if !strings.Contains(fp.gotCmd, "test -f /home/code/.claude/"+f) {
				t.Errorf("probe must test essential file %q, got %q", f, fp.gotCmd)
			}
		}
		if strings.Contains(fp.gotCmd, "test -d") || strings.Contains(fp.gotCmd, "ls -A") {
			t.Errorf("probe must not be a dir existence/content check: %q", fp.gotCmd)
		}
	})

	t.Run("not seeded when no essential file exists", func(t *testing.T) {
		fa := &fakeDirProbe{seeded: false}
		if toolConfigSeeded(fa, "/home/code", tcf) {
			t.Error("want seeded=false when no essential config file is present")
		}
	})
}
