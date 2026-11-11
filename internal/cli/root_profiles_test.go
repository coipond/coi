package cli

import "testing"

func TestCommandNeedsAllProfiles(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"shell"}, false},
		{[]string{"run"}, false},
		{[]string{"top"}, false},
		{[]string{"list"}, false},
		{[]string{"container", "list"}, false},
		{[]string{"container", "exec"}, false},
		{[]string{"profile", "list"}, true},
		{[]string{"profile", "show"}, true},
		{[]string{"health"}, true},
		{[]string{"build"}, true},
		{[]string{"clean"}, true},
		{[]string{"validate", "profile"}, true},
	}
	for _, tt := range tests {
		cmd, _, err := rootCmd.Find(tt.args)
		if err != nil {
			t.Fatalf("Find(%v): %v", tt.args, err)
		}
		if got := commandNeedsAllProfiles(cmd); got != tt.want {
			t.Errorf("commandNeedsAllProfiles(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
	if commandNeedsAllProfiles(rootCmd) {
		t.Error("bare coi runs coi shell and needs one profile")
	}
}
