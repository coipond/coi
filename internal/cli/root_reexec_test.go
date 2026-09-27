package cli

import "testing"

func TestCommandUsesIncusGroup(t *testing.T) {
	// Must NOT re-exec: no Incus access, or must observe real session state.
	for _, name := range []string{"completion", "__complete", "__completeNoDesc", "health", "version", "help"} {
		if commandUsesIncusGroup(name) {
			t.Errorf("%q must be excluded from incus-group re-exec", name)
		}
	}
	// Should re-exec: these touch Incus and benefit from a transparent group activation.
	for _, name := range []string{"shell", "build", "run", "list", "kill", "clean", "attach", "images", "coi"} {
		if !commandUsesIncusGroup(name) {
			t.Errorf("%q should be eligible for incus-group re-exec", name)
		}
	}
}
