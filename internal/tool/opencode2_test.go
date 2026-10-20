package tool

import (
	"reflect"
	"slices"
	"testing"
)

func TestOpencode2Tool_Basics(t *testing.T) {
	oc := NewOpencode2()

	if oc.Name() != "opencode2" {
		t.Errorf("Name() = %q, want %q", oc.Name(), "opencode2")
	}
	if oc.Binary() != "opencode2" {
		t.Errorf("Binary() = %q, want %q", oc.Binary(), "opencode2")
	}
	if oc.ConfigDirName() != ".config/opencode" {
		t.Errorf("ConfigDirName() = %q, want %q", oc.ConfigDirName(), ".config/opencode")
	}
	if oc.SessionsDirName() != "sessions-opencode2" {
		t.Errorf("SessionsDirName() = %q, want %q", oc.SessionsDirName(), "sessions-opencode2")
	}
}

func TestOpencode2Tool_BuildCommand(t *testing.T) {
	oc := NewOpencode2()
	tests := []struct {
		name            string
		resume          bool
		resumeSessionID string
		want            []string
	}{
		{"new", false, "", []string{"opencode2"}},
		{"continue", true, "", []string{"opencode2", "--continue"}},
		{"session", true, "ses_abc", []string{"opencode2", "--session", "ses_abc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := oc.BuildCommand("coi-session", tt.resume, tt.resumeSessionID)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BuildCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpencode2Tool_BuildHeadlessCommand(t *testing.T) {
	oc := NewOpencode2().(ToolWithHeadlessPrompt)
	got, err := oc.BuildHeadlessCommand(LaunchSpec{PromptFile: "/tmp/prompt.txt"})
	if err != nil {
		t.Fatalf("BuildHeadlessCommand() error: %v", err)
	}
	want := []string{"opencode2", "run", "</tmp/prompt.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildHeadlessCommand() = %v, want %v", got, want)
	}
}

func TestOpencode2Tool_SetBinary(t *testing.T) {
	oc := NewOpencode2()
	twb := oc.(ToolWithBinary)

	twb.SetBinary("")
	if oc.Binary() != "opencode2" {
		t.Errorf("empty override: Binary() = %q, want %q", oc.Binary(), "opencode2")
	}

	twb.SetBinary("/opt/opencode/bin/opencode")
	if oc.Binary() != "/opt/opencode/bin/opencode" {
		t.Errorf("override: Binary() = %q, want %q", oc.Binary(), "/opt/opencode/bin/opencode")
	}
	if got := oc.BuildCommand("", false, ""); got[0] != "/opt/opencode/bin/opencode" {
		t.Errorf("BuildCommand()[0] = %q, want the override", got[0])
	}
}

func TestOpencode2Tool_Registered(t *testing.T) {
	got, err := Get("opencode2")
	if err != nil {
		t.Fatalf("Get(opencode2) error: %v", err)
	}
	if got.Name() != "opencode2" {
		t.Errorf("Get(opencode2).Name() = %q", got.Name())
	}
	if slices.Contains(DefaultBuildAgents(), "opencode2") {
		t.Error("opencode2 is opt-in: it must not be in DefaultBuildAgents()")
	}
	if NewOpencode().Binary() != "opencode" {
		t.Errorf("opencode Binary() = %q, want %q", NewOpencode().Binary(), "opencode")
	}
}
