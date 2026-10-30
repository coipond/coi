package cli

import (
	"testing"

	"github.com/coipond/coi/internal/alias"
	"github.com/spf13/cobra"
)

// launchAndRegister runs the profile resolution of a coi shell launch for the
// workspace ws with [container] alias "proj", then registers the alias.
func launchAndRegister(t *testing.T, a *App, cmd *cobra.Command, sessionsDir, ws, aliasArg string) {
	t.Helper()
	a.workspace = ws
	a.cfg.Container.Alias = "proj"
	s := &shellState{aliasArg: aliasArg}
	if _, err := a.resolveWorkspacePhase(cmd, s).Run(t.Context()); err != nil {
		t.Fatalf("resolve-workspace: %v", err)
	}
	if _, _, err := a.resolveResumeAndProfile(cmd, sessionsDir, s.absWorkspace); err != nil {
		t.Fatalf("resolveResumeAndProfile: %v", err)
	}
	if err := a.registerShellAlias(s.absWorkspace); err != nil {
		t.Fatalf("registerShellAlias: %v", err)
	}
}

func savedAliasProfile(t *testing.T) string {
	t.Helper()
	reg, err := alias.Load()
	if err != nil {
		t.Fatal(err)
	}
	entry := reg.Lookup("proj")
	if entry == nil {
		t.Fatal("alias proj was not registered")
	}
	return entry.Profile
}

// A profile that came only from [defaults] profile is not saved into the alias
// registry, so a later change of the default applies to coi shell <alias>.
func TestRegisterShellAlias_DefaultProfileNotSaved(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()

	a, cmd, sessionsDir := newResumeTestApp(t, "work")
	launchAndRegister(t, a, cmd, sessionsDir, ws, "")
	if a.profile != "work" {
		t.Fatalf("a.profile = %q, want the default %q", a.profile, "work")
	}
	if got := savedAliasProfile(t); got != "" {
		t.Errorf("saved alias profile = %q, want none", got)
	}

	a, cmd, sessionsDir = newResumeTestApp(t, "resumed")
	launchAndRegister(t, a, cmd, sessionsDir, ws, "proj")
	if a.profile != "resumed" {
		t.Errorf("coi shell proj ran profile %q, want the new default %q", a.profile, "resumed")
	}
	if got := savedAliasProfile(t); got != "" {
		t.Errorf("saved alias profile = %q, want none", got)
	}
}

// A default-only launch keeps the profile the alias entry already has.
func TestRegisterShellAlias_DefaultProfileKeepsSavedProfile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	reg, err := alias.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("proj", ws, "resumed"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}

	a, cmd, sessionsDir := newResumeTestApp(t, "work")
	launchAndRegister(t, a, cmd, sessionsDir, ws, "")
	if got := savedAliasProfile(t); got != "resumed" {
		t.Errorf("saved alias profile = %q, want %q", got, "resumed")
	}
}

// An explicit --profile is saved, also when [defaults] profile is set.
func TestRegisterShellAlias_ExplicitProfileSaved(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()

	a, cmd, sessionsDir := newResumeTestApp(t, "resumed")
	if err := cmd.Flags().Set("profile", "work"); err != nil {
		t.Fatal(err)
	}
	if err := a.cfg.ApplyProfile("work"); err != nil {
		t.Fatal(err)
	}
	launchAndRegister(t, a, cmd, sessionsDir, ws, "")
	if got := savedAliasProfile(t); got != "work" {
		t.Errorf("saved alias profile = %q, want %q", got, "work")
	}
}
