package cli

import (
	"testing"

	"github.com/coipond/coi/internal/alias"
	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/session"
	"github.com/spf13/cobra"
)

// newResumeTestApp builds an App with a "work" profile (image, cpu, memory)
// and a "resumed" profile (cpu only), the --profile/--resume/--continue/--slot
// flags bound as in root.go, and a sessions dir holding session "sess1" saved
// with profile "resumed".
func newResumeTestApp(t *testing.T, defaultProfile string) (*App, *cobra.Command, string) {
	t.Helper()
	var work, resumed config.ProfileConfig
	work.Container.Image = "coi-work"
	work.Limits = &config.LimitsConfig{CPU: config.CPULimits{Count: "4"}, Memory: config.MemoryLimits{Limit: "8GiB"}}
	resumed.Limits = &config.LimitsConfig{CPU: config.CPULimits{Count: "2"}}
	a, cmd := newProfileTestApp(defaultProfile, map[string]config.ProfileConfig{"work": work, "resumed": resumed})
	cmd.Flags().StringVar(&a.resume, "resume", "", "")
	cmd.Flags().Lookup("resume").NoOptDefVal = "auto"
	cmd.Flags().StringVar(&a.continueSession, "continue", "", "")
	cmd.Flags().IntVar(&a.slot, "slot", 0, "")

	sessionsDir := t.TempDir()
	if err := session.SaveMetadataEarly(sessionsDir, "sess1", "coi-abcd1234-1", "/ws", false, "resumed", false); err != nil {
		t.Fatal(err)
	}
	return a, cmd, sessionsDir
}

func assertProfileApplied(t *testing.T, a *App, name, image, cpu, memory string) {
	t.Helper()
	if a.profile != name {
		t.Errorf("a.profile = %q, want %q", a.profile, name)
	}
	if a.cfg.Container.Image != image {
		t.Errorf("Container.Image = %q, want %q", a.cfg.Container.Image, image)
	}
	if a.cfg.Limits.CPU.Count != cpu {
		t.Errorf("Limits.CPU.Count = %q, want %q", a.cfg.Limits.CPU.Count, cpu)
	}
	if a.cfg.Limits.Memory.Limit != memory {
		t.Errorf("Limits.Memory.Limit = %q, want %q", a.cfg.Limits.Memory.Limit, memory)
	}
}

// An alias-saved profile outranks the resumed session's profile, and the
// resumed one is not merged on top of it.
func TestResolveResumeAndProfile_AliasProfileBeatsResume(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ws := t.TempDir()
	reg, err := alias.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("proj", ws, "work"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}

	a, cmd, sessionsDir := newResumeTestApp(t, "")
	a.workspace = ws
	s := &shellState{aliasArg: "proj"}
	if _, err := a.resolveWorkspacePhase(cmd, s).Run(t.Context()); err != nil {
		t.Fatalf("resolve-workspace: %v", err)
	}
	if err := cmd.Flags().Set("resume", "sess1"); err != nil {
		t.Fatal(err)
	}

	resumeID, metadata, err := a.resolveResumeAndProfile(cmd, sessionsDir, s.absWorkspace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resumeID != "sess1" || metadata == nil {
		t.Fatalf("resumeID = %q, metadata = %v; want sess1 with metadata", resumeID, metadata)
	}
	assertProfileApplied(t, a, "work", "coi-work", "4", "8GiB")
}

// [defaults] profile is the lowest source: a resumed session's profile
// replaces it, so nothing from the default leaks into the resumed session.
func TestResolveResumeAndProfile_ResumeProfileReplacesDefault(t *testing.T) {
	a, cmd, sessionsDir := newResumeTestApp(t, "work")
	baseImage := a.cfg.Container.Image
	if err := cmd.Flags().Set("resume", "sess1"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := a.resolveResumeAndProfile(cmd, sessionsDir, "/ws"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertProfileApplied(t, a, "resumed", baseImage, "2", "")
}

// An explicit --profile wins over the resumed session's profile.
func TestResolveResumeAndProfile_ExplicitProfileBeatsResume(t *testing.T) {
	a, cmd, sessionsDir := newResumeTestApp(t, "")
	if err := cmd.Flags().Set("profile", "work"); err != nil {
		t.Fatal(err)
	}
	// PersistentPreRunE applies an explicit --profile.
	if err := a.cfg.ApplyProfile("work"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("resume", "sess1"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := a.resolveResumeAndProfile(cmd, sessionsDir, "/ws"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertProfileApplied(t, a, "work", "coi-work", "4", "8GiB")
}

// With no explicit, alias or default profile, the resumed session's profile
// applies.
func TestResolveResumeAndProfile_ResumeProfileAlone(t *testing.T) {
	a, cmd, sessionsDir := newResumeTestApp(t, "")
	baseImage := a.cfg.Container.Image
	if err := cmd.Flags().Set("resume", "sess1"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := a.resolveResumeAndProfile(cmd, sessionsDir, "/ws"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertProfileApplied(t, a, "resumed", baseImage, "2", "")
}

// A new session (no resume) still gets [defaults] profile.
func TestResolveResumeAndProfile_DefaultWithoutResume(t *testing.T) {
	a, cmd, sessionsDir := newResumeTestApp(t, "work")

	resumeID, metadata, err := a.resolveResumeAndProfile(cmd, sessionsDir, "/ws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resumeID != "" || metadata != nil {
		t.Fatalf("resumeID = %q, metadata = %v; want a new session", resumeID, metadata)
	}
	assertProfileApplied(t, a, "work", "coi-work", "4", "8GiB")
}

// Auto-resume looks sessions up under the default profile's session_name,
// then applies the found session's profile instead of the default.
func TestResolveResumeAndProfile_AutoResumeUsesDefaultSessionName(t *testing.T) {
	a, cmd, sessionsDir := newResumeTestApp(t, "named")
	baseImage := a.cfg.Container.Image
	var named config.ProfileConfig
	named.Container.SessionName = "team"
	named.Container.Image = "coi-named"
	a.cfg.Profiles["named"] = named

	name := session.GetContainerPrefix() + session.IdentityHash("/ws", "team") + "-1"
	if err := session.SaveMetadataEarly(sessionsDir, "sess-team", name, "/ws", false, "resumed", false); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("resume", "auto"); err != nil {
		t.Fatal(err)
	}

	resumeID, _, err := a.resolveResumeAndProfile(cmd, sessionsDir, "/ws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resumeID != "sess-team" {
		t.Errorf("resumeID = %q, want the session saved under session_name %q", resumeID, "team")
	}
	assertProfileApplied(t, a, "resumed", baseImage, "2", "")
}
