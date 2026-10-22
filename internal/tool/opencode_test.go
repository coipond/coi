package tool

import (
	"reflect"
	"strings"
	"testing"
)

func TestOpencodeTool_Basics(t *testing.T) {
	oc := NewOpencode()

	if oc.Name() != "opencode" {
		t.Errorf("Name() = %q, want %q", oc.Name(), "opencode")
	}
	if oc.Binary() != "opencode" {
		t.Errorf("Binary() = %q, want %q", oc.Binary(), "opencode")
	}
	if oc.ConfigDirName() != ".config/opencode" {
		t.Errorf("ConfigDirName() = %q, want %q", oc.ConfigDirName(), ".config/opencode")
	}
	if oc.SessionsDirName() != "sessions-opencode" {
		t.Errorf("SessionsDirName() = %q, want %q", oc.SessionsDirName(), "sessions-opencode")
	}
}

func TestOpencodeTool_BuildCommand_NewSession(t *testing.T) {
	oc := NewOpencode()
	cmd := oc.BuildCommand("some-session-id", false, "")
	if len(cmd) != 1 || cmd[0] != "opencode" {
		t.Errorf("BuildCommand(new) = %v, want [opencode]", cmd)
	}
}

func TestOpencodeTool_BuildCommand_Resume(t *testing.T) {
	oc := NewOpencode()
	cmd := oc.BuildCommand("", true, "")
	expected := []string{"opencode", "--continue"}
	if len(cmd) != len(expected) {
		t.Fatalf("BuildCommand(resume) = %v, want %v", cmd, expected)
	}
	for i, v := range expected {
		if cmd[i] != v {
			t.Errorf("BuildCommand(resume)[%d] = %q, want %q", i, cmd[i], v)
		}
	}
}

func TestOpencodeTool_BuildCommand_ResumeWithID(t *testing.T) {
	oc := NewOpencode()
	cmd := oc.BuildCommand("", true, "some-id")
	expected := []string{"opencode", "--session", "some-id"}
	if len(cmd) != len(expected) {
		t.Fatalf("BuildCommand(resume with ID) = %v, want %v", cmd, expected)
	}
	for i, v := range expected {
		if cmd[i] != v {
			t.Errorf("BuildCommand(resume with ID)[%d] = %q, want %q", i, cmd[i], v)
		}
	}
}

func TestOpencodeTool_BuildHeadlessCommand(t *testing.T) {
	oc := NewOpencode().(ToolWithHeadlessPrompt)
	tests := []struct {
		name string
		spec LaunchSpec
		want string
	}{
		{"no prompt", LaunchSpec{SessionID: "sid", Print: true}, `opencode run </dev/null`},
		{"fresh", LaunchSpec{SessionID: "sid", PromptFile: "/run/p", Print: true}, `opencode run </run/p`},
		{"continue", LaunchSpec{Resume: true, PromptFile: "/run/p", Print: true}, `opencode run --continue </run/p`},
		{"session", LaunchSpec{Resume: true, ResumeSessionID: "ses_1", PromptFile: "/run/p", Print: true}, `opencode run --session ses_1 </run/p`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := oc.BuildHeadlessCommand(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(cmd, " "); got != tt.want {
				t.Errorf("BuildHeadlessCommand = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOpencodeTool_BuildHeadlessCommand_Binary(t *testing.T) {
	oc := &OpencodeTool{}
	oc.SetBinary("/opt/bin/opencode")
	cmd, err := oc.BuildHeadlessCommand(LaunchSpec{PromptFile: "/run/p", Print: true})
	if err != nil {
		t.Fatal(err)
	}
	if cmd[0] != "/opt/bin/opencode" || cmd[1] != "run" {
		t.Errorf("BuildHeadlessCommand = %v, want the [tool] binary then run", cmd)
	}
}

func TestOpencodeTool_BuildHeadlessCommand_SystemPromptRejected(t *testing.T) {
	oc := NewOpencode().(ToolWithHeadlessPrompt)
	if _, err := oc.BuildHeadlessCommand(LaunchSpec{SystemPromptFile: "/run/s", Print: true}); err == nil {
		t.Error("opencode run has no system-prompt flag; expected an error")
	}
}

func TestOpencodeTool_DiscoverSessionID(t *testing.T) {
	oc := NewOpencode()
	id := oc.DiscoverSessionID("/some/path")
	if id != "" {
		t.Errorf("DiscoverSessionID() = %q, want %q", id, "")
	}
}

func TestOpencodeTool_SessionDiscoveryCommand(t *testing.T) {
	oc := NewOpencode().(*OpencodeTool)
	cmd := oc.SessionDiscoveryCommand("/work'space")
	want := []string{
		"opencode", "db",
		"SELECT id FROM session WHERE parent_id IS NULL AND time_archived IS NULL" +
			" AND directory = '/work''space' ORDER BY time_updated DESC LIMIT 1",
		"--format", "json",
	}
	if strings.Join(cmd, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("SessionDiscoveryCommand() = %q, want %q", cmd, want)
	}

	oc.SetBinary("/opt/oc/bin/opencode")
	if got := oc.SessionDiscoveryCommand("/workspace")[0]; got != "/opt/oc/bin/opencode" {
		t.Errorf("SessionDiscoveryCommand()[0] = %q, want the [tool] binary override", got)
	}
}

func TestOpencodeTool_SetSessionDiscoveryOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"one row", "[\n  {\n    \"id\": \"ses_1a2B3c\"\n  }\n]\n", "ses_1a2B3c"},
		{"log line before the rows", "INFO migrating\n[{\"id\":\"ses_x9\"}]", "ses_x9"},
		{"no rows", "[]\n", ""},
		{"empty output", "", ""},
		{"not json", "Error: no such table: session", ""},
		{"unexpected id shape", `[{"id":"ses_1; rm -rf /"}]`, ""},
		{"not an opencode id", `[{"id":"abc"}]`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oc := NewOpencode().(*OpencodeTool)
			oc.SetSessionDiscoveryOutput(tt.output)
			if got := oc.DiscoverSessionID("/ignored"); got != tt.want {
				t.Errorf("DiscoverSessionID() = %q, want %q", got, tt.want)
			}
			if got := strings.Join(oc.BuildCommand("", true, oc.DiscoverSessionID("")), " "); tt.want != "" && got != "opencode --session "+tt.want {
				t.Errorf("BuildCommand(resume) = %q, want --session %s", got, tt.want)
			}
		})
	}
}

func TestOpencodeTool_SetSessionDiscoveryOutput_ClearsPrevious(t *testing.T) {
	oc := NewOpencode().(*OpencodeTool)
	oc.SetSessionDiscoveryOutput(`[{"id":"ses_old"}]`)
	oc.SetSessionDiscoveryOutput("[]")
	if got := oc.DiscoverSessionID(""); got != "" {
		t.Errorf("DiscoverSessionID() = %q, want \"\" after an empty lookup", got)
	}
}

func TestOpencodeTool_GetSandboxSettings(t *testing.T) {
	oc := NewOpencode()
	settings := oc.GetSandboxSettings()

	perm, ok := settings["permission"]
	if !ok {
		t.Fatal("GetSandboxSettings() missing 'permission' key")
	}
	permMap, ok := perm.(map[string]interface{})
	if !ok {
		t.Fatalf("'permission' value is %T, want map[string]interface{}", perm)
	}
	val, ok := permMap["*"]
	if !ok {
		t.Fatal("permission map missing '*' key")
	}
	if val != "allow" {
		t.Errorf("permission['*'] = %q, want %q", val, "allow")
	}
}

func TestOpencodeTool_EssentialConfigFiles(t *testing.T) {
	oc := NewOpencode()
	tcf, ok := oc.(ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("OpencodeTool does not implement ToolWithConfigDirFiles")
	}
	files := tcf.EssentialConfigFiles()
	expected := []string{"opencode.json", "tui.json"}
	if len(files) != len(expected) {
		t.Fatalf("EssentialConfigFiles() = %v, want %v", files, expected)
	}
	for i, f := range files {
		if f != expected[i] {
			t.Errorf("EssentialConfigFiles()[%d] = %q, want %q", i, f, expected[i])
		}
	}
}

func TestOpencodeTool_SandboxSettingsFileName(t *testing.T) {
	oc := NewOpencode()
	tcf, ok := oc.(ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("OpencodeTool does not implement ToolWithConfigDirFiles")
	}
	if tcf.SandboxSettingsFileName() != "opencode.json" {
		t.Errorf("SandboxSettingsFileName() = %q, want %q", tcf.SandboxSettingsFileName(), "opencode.json")
	}
}

func TestOpencodeTool_StateConfigFileName(t *testing.T) {
	oc := NewOpencode()
	tcf, ok := oc.(ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("OpencodeTool does not implement ToolWithConfigDirFiles")
	}
	if tcf.StateConfigFileName() != "" {
		t.Errorf("StateConfigFileName() = %q, want %q", tcf.StateConfigFileName(), "")
	}
}

func TestOpencodeTool_AlwaysSetupConfig(t *testing.T) {
	oc := NewOpencode()
	tcf, ok := oc.(ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("OpencodeTool does not implement ToolWithConfigDirFiles")
	}
	if !tcf.AlwaysSetupConfig() {
		t.Error("AlwaysSetupConfig() = false, want true")
	}
}

func TestOpencodeTool_RegistryLookup(t *testing.T) {
	oc, err := Get("opencode")
	if err != nil {
		t.Fatalf("Get(\"opencode\") returned error: %v", err)
	}
	if oc.Name() != "opencode" {
		t.Errorf("Name() = %q, want %q", oc.Name(), "opencode")
	}
}

func TestOpencodeTool_ImplementsPermissionMode(t *testing.T) {
	oc := NewOpencode()

	twpm, ok := oc.(ToolWithPermissionMode)
	if !ok {
		t.Fatal("OpencodeTool should implement ToolWithPermissionMode")
	}

	// Verify method works without panic
	twpm.SetPermissionMode("interactive")
}

func TestOpencodeTool_GetSandboxSettings_InteractiveMode(t *testing.T) {
	oc := &OpencodeTool{permissionMode: "interactive"}
	settings := oc.GetSandboxSettings()

	perm, ok := settings["permission"]
	if !ok {
		t.Fatal("GetSandboxSettings() missing 'permission' key in interactive mode")
	}
	permMap, ok := perm.(map[string]interface{})
	if !ok {
		t.Fatalf("'permission' value is %T, want map[string]interface{}", perm)
	}
	val, ok := permMap["*"]
	if !ok {
		t.Fatal("permission map missing '*' key in interactive mode")
	}
	if val != "ask" {
		t.Errorf("permission['*'] = %q, want %q", val, "ask")
	}
}

func TestOpencodeTool_GetSandboxSettings_BypassDefault(t *testing.T) {
	oc := &OpencodeTool{} // Empty permissionMode = default bypass
	settings := oc.GetSandboxSettings()

	perm, ok := settings["permission"]
	if !ok {
		t.Fatal("GetSandboxSettings() missing 'permission' key in bypass mode")
	}
	permMap, ok := perm.(map[string]interface{})
	if !ok {
		t.Fatalf("'permission' value is %T, want map[string]interface{}", perm)
	}
	val, ok := permMap["*"]
	if !ok {
		t.Fatal("permission map missing '*' key")
	}
	if val != "allow" {
		t.Errorf("permission['*'] = %q, want %q", val, "allow")
	}
}

func TestOpencodeTool_ContainerEnvIsEmpty(t *testing.T) {
	oc := NewOpencode()

	twce, ok := oc.(ToolWithContainerEnv)
	if !ok {
		t.Fatal("OpencodeTool should keep implementing ToolWithContainerEnv so stale XDG env gets unset")
	}
	if env := twce.GetContainerEnv("/workspace"); len(env) != 0 {
		t.Errorf("GetContainerEnv() = %v, want empty: data dirs are host mounts now, not workspace redirects (#929)", env)
	}
}

func TestOpencodeTool_DataDirs(t *testing.T) {
	tdd, ok := NewOpencode().(ToolWithDataDirs)
	if !ok {
		t.Fatal("OpencodeTool should implement ToolWithDataDirs")
	}
	want := []DataDir{
		{Name: "share", HomeRelPath: ".local/share/opencode"},
		{Name: "state", HomeRelPath: ".local/state/opencode"},
	}
	if got := tdd.DataDirs(); !reflect.DeepEqual(got, want) {
		t.Errorf("DataDirs() = %v, want %v", got, want)
	}
}

func TestOpencodeTool_SetAutoContextPath(t *testing.T) {
	oc := NewOpencode()

	acp, ok := oc.(ToolWithAutoContextPath)
	if !ok {
		t.Fatal("OpencodeTool should implement ToolWithAutoContextPath")
	}

	// Verify method works without panic
	acp.SetAutoContextPath("/home/code/SANDBOX_CONTEXT.md")
}

func TestOpencodeTool_GetSandboxSettings_WithAutoContext(t *testing.T) {
	oc := &OpencodeTool{contextFilePath: "/home/code/SANDBOX_CONTEXT.md"}
	settings := oc.GetSandboxSettings()

	// Should have instructions field
	instructions, ok := settings["instructions"]
	if !ok {
		t.Fatal("GetSandboxSettings() missing 'instructions' key when contextFilePath is set")
	}
	instrSlice, ok := instructions.([]string)
	if !ok {
		t.Fatalf("'instructions' value is %T, want []string", instructions)
	}
	if len(instrSlice) != 1 || instrSlice[0] != "/home/code/SANDBOX_CONTEXT.md" {
		t.Errorf("instructions = %v, want [/home/code/SANDBOX_CONTEXT.md]", instrSlice)
	}

	// Should still have permission field
	if _, ok := settings["permission"]; !ok {
		t.Error("GetSandboxSettings() missing 'permission' key")
	}
}

func TestOpencodeTool_GetSandboxSettings_WithoutAutoContext(t *testing.T) {
	oc := &OpencodeTool{} // No contextFilePath set
	settings := oc.GetSandboxSettings()

	// Should NOT have instructions field
	if _, ok := settings["instructions"]; ok {
		t.Error("GetSandboxSettings() should not have 'instructions' key when contextFilePath is empty")
	}

	// Should still have permission field
	if _, ok := settings["permission"]; !ok {
		t.Error("GetSandboxSettings() missing 'permission' key")
	}
}

func TestOpencodeTool_GetSandboxSettings_InteractiveWithAutoContext(t *testing.T) {
	oc := &OpencodeTool{
		permissionMode:  "interactive",
		contextFilePath: "/home/code/SANDBOX_CONTEXT.md",
	}
	settings := oc.GetSandboxSettings()

	// Should have instructions field
	if _, ok := settings["instructions"]; !ok {
		t.Error("GetSandboxSettings() missing 'instructions' key in interactive mode")
	}

	// Permission should be "ask" in interactive mode
	perm, ok := settings["permission"]
	if !ok {
		t.Fatal("GetSandboxSettings() missing 'permission' key")
	}
	permMap := perm.(map[string]interface{})
	if permMap["*"] != "ask" {
		t.Errorf("permission['*'] = %q, want %q", permMap["*"], "ask")
	}
}

func TestListSupported_IncludesOpencode(t *testing.T) {
	supported := ListSupported()
	found := false
	for _, name := range supported {
		if name == "opencode" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListSupported() = %v, does not include 'opencode'", supported)
	}
}
