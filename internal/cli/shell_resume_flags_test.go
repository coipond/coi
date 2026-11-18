package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/alias"
	"github.com/coipond/coi/internal/session"
)

// writeSession saves session id for workspace ws at savedAt.
func writeSession(t *testing.T, sessionsDir, id, ws, savedAt string) {
	t.Helper()
	dir := filepath.Join(sessionsDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(session.SessionMetadata{
		SessionID:     id,
		ContainerName: session.ContainerName(ws, "", 1),
		Workspace:     ws,
		SavedAt:       savedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPickResumeID(t *testing.T) {
	tests := []struct {
		name, resume, cont, want string
		warn                     bool
	}{
		{"neither", "", "", "", false},
		{"resume only", "sessA", "", "sessA", false},
		{"continue only", "", "sessA", "sessA", false},
		{"bare both", "auto", "auto", "auto", false},
		{"same id", "sessA", "sessA", "sessA", false},
		{"id beats bare continue", "sessA", "auto", "sessA", true},
		{"continue id beats bare resume", "auto", "sessA", "sessA", true},
		{"resume beats continue id", "sessA", "sessB", "sessA", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warning := pickResumeID(tt.resume, tt.cont)
			if got != tt.want {
				t.Errorf("pickResumeID(%q, %q) = %q, want %q", tt.resume, tt.cont, got, tt.want)
			}
			if (warning != "") != tt.warn {
				t.Errorf("pickResumeID(%q, %q) warning = %q, want warning: %v", tt.resume, tt.cont, warning, tt.warn)
			}
		})
	}
}

// --resume=<id> together with a bare --continue, or with a different
// --continue=<id>, resumes the --resume session, not the latest one, and
// warns which flag was ignored.
func TestResolveResumeAndProfile_ResumeIDBeatsContinue(t *testing.T) {
	tests := []struct {
		name  string
		flags [][2]string
	}{
		{"resume then bare continue", [][2]string{{"resume", "sessA"}, {"continue", "auto"}}},
		{"bare continue then resume", [][2]string{{"continue", "auto"}, {"resume", "sessA"}}},
		{"different continue id", [][2]string{{"resume", "sessA"}, {"continue", "sessB"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := t.TempDir()
			a, cmd, sessionsDir := newResumeTestApp(t, "")
			writeSession(t, sessionsDir, "sessA", ws, "2026-01-01T00:00:00Z")
			writeSession(t, sessionsDir, "sessB", ws, "2026-02-01T00:00:00Z")
			for _, f := range tt.flags {
				if err := cmd.Flags().Set(f[0], f[1]); err != nil {
					t.Fatal(err)
				}
			}

			var resumeID string
			stderr := captureOutput(t, &os.Stderr, func() {
				var err error
				if resumeID, _, err = a.resolveResumeAndProfile(cmd, sessionsDir, ws); err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			})
			if resumeID != "sessA" {
				t.Errorf("resumeID = %q, want sessA", resumeID)
			}
			if strings.Count(stderr, "Warning:") != 1 || !strings.Contains(stderr, "--continue") {
				t.Errorf("stderr = %q, want one warning naming the ignored --continue", stderr)
			}
		})
	}
}

// The same session ID in both flags resumes it with no warning.
func TestResolveResumeAndProfile_SameIDNoWarning(t *testing.T) {
	ws := t.TempDir()
	a, cmd, sessionsDir := newResumeTestApp(t, "")
	writeSession(t, sessionsDir, "sessA", ws, "2026-01-01T00:00:00Z")
	for _, f := range []string{"resume", "continue"} {
		if err := cmd.Flags().Set(f, "sessA"); err != nil {
			t.Fatal(err)
		}
	}

	stderr := captureOutput(t, &os.Stderr, func() {
		resumeID, _, err := a.resolveResumeAndProfile(cmd, sessionsDir, ws)
		if err != nil || resumeID != "sessA" {
			t.Errorf("resumeID = %q, err = %v; want sessA", resumeID, err)
		}
	})
	if strings.Contains(stderr, "Warning:") {
		t.Errorf("stderr = %q, want no warning", stderr)
	}
}

// An unknown --resume ID with a bare --continue fails with the not-found
// error and prints no conflict warning.
func TestResolveResumeAndProfile_UnknownResumeIDNoWarning(t *testing.T) {
	ws := t.TempDir()
	a, cmd, sessionsDir := newResumeTestApp(t, "")
	writeSession(t, sessionsDir, "sessB", ws, "2026-02-01T00:00:00Z")
	for _, f := range [][2]string{{"resume", "bogus"}, {"continue", "auto"}} {
		if err := cmd.Flags().Set(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}

	stderr := captureOutput(t, &os.Stderr, func() {
		if _, _, err := a.resolveResumeAndProfile(cmd, sessionsDir, ws); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("err = %v, want session not found", err)
		}
	})
	if strings.Contains(stderr, "Warning:") {
		t.Errorf("stderr = %q, want no warning", stderr)
	}
}

// resolveAliasWorkspace runs resolve-workspace for alias "proj" (registered
// for aliasWS) with the given -w (none when empty) and returns the workspace
// and stderr.
func resolveAliasWorkspace(t *testing.T, aliasWS, workspaceFlag string) (got, stderr string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	reg, err := alias.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("proj", aliasWS, ""); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}

	a, cmd, _ := newResumeTestApp(t, "")
	cmd.Flags().StringVarP(&a.workspace, "workspace", "w", ".", "")
	if workspaceFlag != "" {
		if err := cmd.Flags().Set("workspace", workspaceFlag); err != nil {
			t.Fatal(err)
		}
	}
	s := &shellState{aliasArg: "proj"}
	stderr = captureOutput(t, &os.Stderr, func() {
		if _, err := a.resolveWorkspacePhase(cmd, s).Run(t.Context()); err != nil {
			t.Errorf("resolve-workspace: %v", err)
		}
	})
	return s.absWorkspace, stderr
}

// An alias still wins over an explicit -w, with a warning naming the
// ignored directory.
func TestResolveWorkspacePhase_AliasWithWorkspaceFlagWarns(t *testing.T) {
	aliasWS, other := t.TempDir(), t.TempDir()
	got, stderr := resolveAliasWorkspace(t, aliasWS, other)
	if got != aliasWS {
		t.Errorf("workspace = %q, want the alias workspace %q", got, aliasWS)
	}
	if strings.Count(stderr, "Warning:") != 1 || !strings.Contains(stderr, other) {
		t.Errorf("stderr = %q, want one warning naming -w %s", stderr, other)
	}
}

// An alias without -w prints no warning.
func TestResolveWorkspacePhase_AliasWithoutWorkspaceFlagNoWarning(t *testing.T) {
	aliasWS := t.TempDir()
	got, stderr := resolveAliasWorkspace(t, aliasWS, "")
	if got != aliasWS {
		t.Errorf("workspace = %q, want the alias workspace %q", got, aliasWS)
	}
	if strings.Contains(stderr, "Warning:") {
		t.Errorf("stderr = %q, want no warning", stderr)
	}
}

// -w naming the alias's own workspace prints no warning.
func TestResolveWorkspacePhase_AliasWithSameWorkspaceFlagNoWarning(t *testing.T) {
	aliasWS := t.TempDir()
	got, stderr := resolveAliasWorkspace(t, aliasWS, aliasWS)
	if got != aliasWS {
		t.Errorf("workspace = %q, want the alias workspace %q", got, aliasWS)
	}
	if strings.Contains(stderr, "Warning:") {
		t.Errorf("stderr = %q, want no warning", stderr)
	}
}
