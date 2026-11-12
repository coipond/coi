package tool

import (
	"reflect"
	"slices"
	"testing"

	"github.com/coipond/coi/internal/tool/credentials"
)

func TestGooseTool_Basics(t *testing.T) {
	goose := NewGoose()

	if goose.Name() != "goose" {
		t.Errorf("Name() = %q, want %q", goose.Name(), "goose")
	}
	if goose.Binary() != "goose" {
		t.Errorf("Binary() = %q, want %q", goose.Binary(), "goose")
	}
	if goose.ConfigDirName() != ".config/goose" {
		t.Errorf("ConfigDirName() = %q, want %q", goose.ConfigDirName(), ".config/goose")
	}
	if goose.SessionsDirName() != "sessions-goose" {
		t.Errorf("SessionsDirName() = %q, want %q", goose.SessionsDirName(), "sessions-goose")
	}
	if id := goose.DiscoverSessionID("/some/path"); id != "" {
		t.Errorf("DiscoverSessionID() = %q, want %q", id, "")
	}
}

func TestGooseTool_BuildCommand_New(t *testing.T) {
	goose := NewGoose()
	want := []string{"goose", "session"}
	if got := goose.BuildCommand("some-session-id", false, ""); !reflect.DeepEqual(got, want) {
		t.Errorf("BuildCommand(new) = %v, want %v", got, want)
	}
}

func TestGooseTool_SetBinary(t *testing.T) {
	goose := NewGoose()
	twb, ok := goose.(ToolWithBinary)
	if !ok {
		t.Fatal("GooseTool does not implement ToolWithBinary")
	}

	twb.SetBinary("goose; rm -rf /")
	if goose.Binary() != "goose" {
		t.Errorf("unsafe override: Binary() = %q, want %q", goose.Binary(), "goose")
	}

	twb.SetBinary("/opt/goose/bin/goose")
	if goose.Binary() != "/opt/goose/bin/goose" {
		t.Errorf("override: Binary() = %q, want %q", goose.Binary(), "/opt/goose/bin/goose")
	}
	want := []string{"/opt/goose/bin/goose", "session"}
	if got := goose.BuildCommand("", false, ""); !reflect.DeepEqual(got, want) {
		t.Errorf("BuildCommand() = %v, want %v", got, want)
	}
}

func TestGooseTool_SandboxSettingsEmpty(t *testing.T) {
	goose := NewGoose()
	if settings := goose.GetSandboxSettings(); len(settings) != 0 {
		t.Errorf("GetSandboxSettings() = %v, want empty map", settings)
	}
}

func TestGooseTool_ConfigFiles(t *testing.T) {
	goose := NewGoose()
	tcf, ok := goose.(ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("GooseTool does not implement ToolWithConfigDirFiles")
	}
	b, ok := credentials.Lookup("goose")
	if !ok {
		t.Fatal("goose bundle not found")
	}
	if !reflect.DeepEqual(tcf.EssentialConfigFiles(), b.Files) {
		t.Errorf("EssentialConfigFiles() = %v, want the bundle's %v", tcf.EssentialConfigFiles(), b.Files)
	}
	if tcf.SandboxSettingsFileName() != "" {
		t.Errorf("SandboxSettingsFileName() = %q, want empty", tcf.SandboxSettingsFileName())
	}
	if tcf.StateConfigFileName() != "" {
		t.Errorf("StateConfigFileName() = %q, want empty", tcf.StateConfigFileName())
	}
	if tcf.AlwaysSetupConfig() {
		t.Error("AlwaysSetupConfig() = true, want false")
	}
}

func TestGooseTool_PermissionModeStored(t *testing.T) {
	goose := NewGoose()
	twp, ok := goose.(ToolWithPermissionMode)
	if !ok {
		t.Fatal("GooseTool does not implement ToolWithPermissionMode")
	}
	twp.SetPermissionMode("interactive")
	if got := goose.(*GooseTool).permissionMode; got != "interactive" {
		t.Errorf("permissionMode = %q, want %q", got, "interactive")
	}
}

func TestGooseTool_RegistryLookup(t *testing.T) {
	goose, err := Get("goose")
	if err != nil {
		t.Fatalf("Get(\"goose\") returned error: %v", err)
	}
	if goose.Name() != "goose" {
		t.Errorf("Name() = %q, want %q", goose.Name(), "goose")
	}
	if !slices.Contains(ListSupported(), "goose") {
		t.Errorf("ListSupported() = %v, does not include 'goose'", ListSupported())
	}
	if slices.Contains(DefaultBuildAgents(), "goose") {
		t.Errorf("DefaultBuildAgents() = %v, goose must stay opt-in", DefaultBuildAgents())
	}
}

func TestGooseTool_BuildCommand_Resume(t *testing.T) {
	goose := NewGoose()
	want := []string{"goose", "session", "--resume", "--session-id", "20261107_3"}
	if got := goose.BuildCommand("", true, "20261107_3"); !reflect.DeepEqual(got, want) {
		t.Errorf("BuildCommand(resume, id) = %v, want %v", got, want)
	}
	want = []string{"goose", "session"}
	if got := goose.BuildCommand("", true, ""); !reflect.DeepEqual(got, want) {
		t.Errorf("BuildCommand(resume, no id) = %v, want %v", got, want)
	}
}

func TestGooseTool_SessionDiscoveryCommand(t *testing.T) {
	tcd, ok := NewGoose().(ToolWithContainerSessionDiscovery)
	if !ok {
		t.Fatal("GooseTool does not implement ToolWithContainerSessionDiscovery")
	}
	want := []string{"goose", "session", "list", "--format", "json", "--working_dir", "/workspace"}
	if got := tcd.SessionDiscoveryCommand("/workspace"); !reflect.DeepEqual(got, want) {
		t.Errorf("SessionDiscoveryCommand() = %v, want %v", got, want)
	}
}

func TestGooseTool_SetSessionDiscoveryOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "exact working_dir beats a newer subdir row",
			output: `[{"id":"20261107_4","working_dir":"/workspace/sub"},{"id":"20261107_3","working_dir":"/workspace"}]`,
			want:   "20261107_3",
		},
		{
			name:   "first exact row is the newest",
			output: `[{"id":"20261107_5","working_dir":"/workspace/"},{"id":"20261107_3","working_dir":"/workspace"}]`,
			want:   "20261107_5",
		},
		{
			name:   "log line before the JSON",
			output: "2026-11-07T10:00:00Z INFO goose: starting\n" + `[{"id":"20261107_1","working_dir":"/workspace"}]`,
			want:   "20261107_1",
		},
		{
			name:   "no sessions",
			output: "[]",
			want:   "",
		},
		{
			name:   "only a subdir session",
			output: `[{"id":"20261107_4","working_dir":"/workspace/sub"}]`,
			want:   "",
		},
		{
			name:   "id with shell metacharacters",
			output: `[{"id":"20261107_1; rm -rf /","working_dir":"/workspace"}]`,
			want:   "",
		},
		{
			name:   "not JSON",
			output: "error: no such command",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goose := NewGoose()
			tcd := goose.(ToolWithContainerSessionDiscovery)
			tcd.SessionDiscoveryCommand("/workspace")
			tcd.SetSessionDiscoveryOutput(tt.output)
			if got := goose.DiscoverSessionID(""); got != tt.want {
				t.Errorf("DiscoverSessionID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGooseTool_SetSessionDiscoveryOutput_ResetsID(t *testing.T) {
	goose := NewGoose()
	tcd := goose.(ToolWithContainerSessionDiscovery)
	tcd.SessionDiscoveryCommand("/workspace")
	tcd.SetSessionDiscoveryOutput(`[{"id":"20261107_1","working_dir":"/workspace"}]`)
	tcd.SetSessionDiscoveryOutput("[]")
	if got := goose.DiscoverSessionID(""); got != "" {
		t.Errorf("DiscoverSessionID() = %q after empty output, want \"\"", got)
	}
}

func TestGooseTool_DataDirs(t *testing.T) {
	tdd, ok := NewGoose().(ToolWithDataDirs)
	if !ok {
		t.Fatal("GooseTool does not implement ToolWithDataDirs")
	}
	want := []DataDir{
		{Name: "share", HomeRelPath: ".local/share/goose"},
		{Name: "state", HomeRelPath: ".local/state/goose"},
	}
	if got := tdd.DataDirs(); !reflect.DeepEqual(got, want) {
		t.Errorf("DataDirs() = %v, want %v", got, want)
	}
}

func TestGooseTool_SessionExcludedFiles(t *testing.T) {
	tse, ok := NewGoose().(ToolWithSessionExcludes)
	if !ok {
		t.Fatal("GooseTool does not implement ToolWithSessionExcludes")
	}
	want := []string{"tls", "roaming_node_key"}
	if got := tse.SessionExcludedFiles(); !reflect.DeepEqual(got, want) {
		t.Errorf("SessionExcludedFiles() = %v, want %v", got, want)
	}
}
