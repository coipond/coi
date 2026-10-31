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
		{"new", false, "", []string{"opencode2", "--standalone", "--auto"}},
		{"continue", true, "", []string{"opencode2", "--standalone", "--auto", "--continue"}},
		{"session", true, "ses_abc", []string{"opencode2", "--standalone", "--auto", "--session", "ses_abc"}},
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

func TestOpencode2Tool_NoSessionDiscovery(t *testing.T) {
	d, ok := NewOpencode2().(ToolWithContainerSessionDiscovery)
	if !ok {
		t.Fatal("Opencode2Tool should implement ToolWithContainerSessionDiscovery (embedded)")
	}
	if got := d.SessionDiscoveryCommand("/workspace"); got != nil {
		t.Errorf("SessionDiscoveryCommand() = %v, want nil", got)
	}
}

func TestOpencode2Tool_DataDirs(t *testing.T) {
	tdd, ok := NewOpencode2().(ToolWithDataDirs)
	if !ok {
		t.Fatal("Opencode2Tool should implement ToolWithDataDirs")
	}
	want := []DataDir{
		{Name: "share", HomeRelPath: ".local/share/opencode"},
		{Name: "state", HomeRelPath: ".local/state/opencode"},
		{Name: "plan", HomeRelPath: ".opencode/plan", FromContainer: true},
	}
	if got := tdd.DataDirs(); !reflect.DeepEqual(got, want) {
		t.Errorf("DataDirs() = %v, want %v", got, want)
	}
}

func TestOpencode2Tool_BuildHeadlessCommand(t *testing.T) {
	oc := NewOpencode2().(ToolWithHeadlessPrompt)
	got, err := oc.BuildHeadlessCommand(LaunchSpec{PromptFile: "/tmp/prompt.txt"})
	if err != nil {
		t.Fatalf("BuildHeadlessCommand() error: %v", err)
	}
	want := []string{"opencode2", "run", "--standalone", "--auto", "</tmp/prompt.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildHeadlessCommand() = %v, want %v", got, want)
	}
}

func TestOpencode2Tool_BuildHeadlessCommand_Resume(t *testing.T) {
	oc := NewOpencode2().(ToolWithHeadlessPrompt)
	got, err := oc.BuildHeadlessCommand(LaunchSpec{Resume: true, ResumeSessionID: "ses_abc"})
	if err != nil {
		t.Fatalf("BuildHeadlessCommand() error: %v", err)
	}
	want := []string{"opencode2", "run", "--standalone", "--auto", "--session", "ses_abc", "</dev/null"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildHeadlessCommand() = %v, want %v", got, want)
	}
	if _, err := oc.BuildHeadlessCommand(LaunchSpec{SystemPromptFile: "/tmp/sys.md"}); err == nil {
		t.Error("BuildHeadlessCommand() with a SystemPromptFile: want an error")
	}
}

// OpenCode v1 has no --standalone or --auto flag: only opencode2 gets them.
func TestOpencodeTool_NoV2Flags(t *testing.T) {
	for _, flag := range []string{"--standalone", "--auto"} {
		if got := NewOpencode().BuildCommand("", true, ""); slices.Contains(got, flag) {
			t.Errorf("opencode BuildCommand() = %v, want no %s", got, flag)
		}
		got, err := NewOpencode().(ToolWithHeadlessPrompt).BuildHeadlessCommand(LaunchSpec{})
		if err != nil || slices.Contains(got, flag) {
			t.Errorf("opencode BuildHeadlessCommand() = %v, %v; want no %s", got, err, flag)
		}
	}
}

// Interactive mode keeps v2's prompts: no --auto.
func TestOpencode2Tool_InteractiveNoAuto(t *testing.T) {
	oc := NewOpencode2()
	oc.(ToolWithPermissionMode).SetPermissionMode("interactive")
	if got, want := oc.BuildCommand("", true, ""), []string{"opencode2", "--standalone", "--continue"}; !reflect.DeepEqual(got, want) {
		t.Errorf("BuildCommand() = %v, want %v", got, want)
	}
	got, err := oc.(ToolWithHeadlessPrompt).BuildHeadlessCommand(LaunchSpec{})
	if want := []string{"opencode2", "run", "--standalone", "</dev/null"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("BuildHeadlessCommand() = %v, %v; want %v", got, err, want)
	}
}

func TestOpencode2Tool_SessionExcludedFiles(t *testing.T) {
	te, ok := NewOpencode2().(ToolWithSessionExcludes)
	if !ok {
		t.Fatal("Opencode2Tool should implement ToolWithSessionExcludes")
	}
	if got, want := te.SessionExcludedFiles(), []string{"service.json"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SessionExcludedFiles() = %v, want %v", got, want)
	}
	if _, ok := NewOpencode().(ToolWithSessionExcludes); ok {
		t.Error("opencode (v1) should not implement ToolWithSessionExcludes")
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
	if got := oc.BuildCommand("", false, ""); got[0] != "/opt/opencode/bin/opencode" || got[1] != "--standalone" {
		t.Errorf("BuildCommand() = %v, want the override and --standalone", got)
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
	if !slices.Contains(DefaultBuildAgents(), "opencode2") {
		t.Error("opencode2 is a default agent: it must be in DefaultBuildAgents()")
	}
	if slices.Contains(DefaultBuildAgents(), "opencode") {
		t.Error("opencode (v1) is opt-in: it must not be in DefaultBuildAgents()")
	}
	if NewOpencode().Binary() != "opencode" {
		t.Errorf("opencode Binary() = %q, want %q", NewOpencode().Binary(), "opencode")
	}
}

func TestOpencode2Tool_ConfigFiles(t *testing.T) {
	tcf, ok := NewOpencode2().(ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("Opencode2Tool should implement ToolWithConfigDirFiles")
	}
	if got, want := tcf.EssentialConfigFiles(), []string{"opencode.json", "cli.json"}; !reflect.DeepEqual(got, want) {
		t.Errorf("EssentialConfigFiles() = %v, want %v", got, want)
	}
	if got := tcf.SandboxSettingsFileName(); got != "opencode.json" {
		t.Errorf("SandboxSettingsFileName() = %q, want %q", got, "opencode.json")
	}
	if got := tcf.StateConfigFileName(); got != "" {
		t.Errorf("StateConfigFileName() = %q, want empty", got)
	}
	if !tcf.AlwaysSetupConfig() {
		t.Error("AlwaysSetupConfig() = false, want true")
	}
}

// opencode and opencode2 share ~/.config/opencode/opencode.json, and a
// persistent container keeps the file of whichever tool seeded it, so both
// must write the same sandbox settings: OpenCode v1 rejects V2 keys such as
// `permissions`.
func TestOpencode2Tool_GetSandboxSettings_SameAsOpencode(t *testing.T) {
	for _, mode := range []string{"", "bypass", "interactive"} {
		t.Run(mode, func(t *testing.T) {
			v1, v2 := NewOpencode(), NewOpencode2()
			for _, oc := range []Tool{v1, v2} {
				oc.(ToolWithPermissionMode).SetPermissionMode(mode)
				oc.(ToolWithAutoContextPath).SetAutoContextPath("/home/code/SANDBOX_CONTEXT.md")
			}
			got := v2.GetSandboxSettings()
			if want := v1.GetSandboxSettings(); !reflect.DeepEqual(got, want) {
				t.Errorf("opencode2 GetSandboxSettings() = %v, want opencode's %v", got, want)
			}
			if _, ok := got["permissions"]; ok {
				t.Errorf("GetSandboxSettings() = %v, want no V2 `permissions` key", got)
			}
		})
	}
}
