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
