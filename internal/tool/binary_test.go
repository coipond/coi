package tool

import (
	"strings"
	"testing"
)

// [tool] binary replaces argv[0] for every tool, keeping the tool's own
// arguments, and Binary() reports the effective executable.
func TestSetBinary_ReplacesExecutable(t *testing.T) {
	for _, tl := range []Tool{NewClaude(), NewCodex(), NewOpencode(), NewPi(), NewOmp()} {
		def := tl.BuildCommand("sid", false, "")
		twb, ok := tl.(ToolWithBinary)
		if !ok {
			t.Fatalf("%s does not implement ToolWithBinary", tl.Name())
		}
		twb.SetBinary("/workspace/wrap.sh")
		got := tl.BuildCommand("sid", false, "")
		if got[0] != "/workspace/wrap.sh" {
			t.Errorf("%s: argv[0] = %q, want the configured binary", tl.Name(), got[0])
		}
		if strings.Join(got[1:], " ") != strings.Join(def[1:], " ") {
			t.Errorf("%s: arguments changed: %v vs default %v", tl.Name(), got[1:], def[1:])
		}
		if tl.Binary() != "/workspace/wrap.sh" {
			t.Errorf("%s: Binary() = %q", tl.Name(), tl.Binary())
		}
	}
}

// Without an override every tool keeps its default executable.
func TestBinary_DefaultsToToolName(t *testing.T) {
	for _, tl := range []Tool{NewClaude(), NewCodex(), NewOpencode(), NewPi(), NewOmp()} {
		if tl.Binary() != tl.Name() {
			t.Errorf("%s: Binary() = %q, want %q", tl.Name(), tl.Binary(), tl.Name())
		}
		if argv := tl.BuildCommand("sid", false, ""); argv[0] != tl.Name() {
			t.Errorf("%s: argv[0] = %q, want %q", tl.Name(), argv[0], tl.Name())
		}
	}
}

func TestValidateBinary(t *testing.T) {
	for value, ok := range map[string]bool{
		"":                          true,
		"claude":                    true,
		"/workspace/wrap.sh":        true,
		"./bin/claude-wrapper":      true,
		"/opt/tools/claude@2.1/bin": true,
		"claude update; claude":     false,
		"/path with space/claude":   false,
		"claude'":                   false,
		"$(evil)":                   false,
		"-x":                        false,
		"claude&&x":                 false,
		"/usr/bin/claude\n":         false,
		"`whoami`":                  false,
	} {
		if err := ValidateBinary(value); (err == nil) != ok {
			t.Errorf("ValidateBinary(%q) err = %v, want ok=%v", value, err, ok)
		}
	}
}

// The setter is fail-closed: an unsafe value never reaches the command line.
func TestSetBinary_IgnoresUnsafeValue(t *testing.T) {
	c := NewClaude().(*ClaudeTool)
	c.SetBinary("claude; rm -rf /")
	if c.Binary() != "claude" {
		t.Errorf("unsafe binary was accepted: %q", c.Binary())
	}
}
