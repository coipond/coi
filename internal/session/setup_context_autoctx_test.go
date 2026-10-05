package session

import (
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// fakeAutoCtxManager is an in-memory ContainerManager that simulates just enough
// of a container filesystem for injectAutoContextFile: `mkdir -p`, the
// `test -f … && echo exists || echo missing` existence probe, CreateFile,
// PushFile (staging a host temp file), a plain `cat <path>` read, and a
// `cat <staging> >> <dest>` append. Every other ContainerManager method is
// inherited from the embedded (nil) interface and is never called here, so a
// call to one would panic loudly rather than pass silently.
//
// The simulated filesystem persists across calls (map keyed by path), which is
// exactly the condition that makes #674 reproducible: a persistent container's
// ~/.claude/CLAUDE.md survives from one session to the next.
type fakeAutoCtxManager struct {
	container.ContainerManager
	files map[string]string
}

func newFakeAutoCtxManager() *fakeAutoCtxManager {
	return &fakeAutoCtxManager{files: map[string]string{}}
}

var (
	fakeReadRe  = regexp.MustCompile(`if \[ -f '([^']*)' \]`)
	fakeWriteRe = regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]*)' \| base64 -d > .* mv -f '[^']*' '([^']*)'$`)
)

func (f *fakeAutoCtxManager) ExecCommand(cmd string, _ container.ExecCommandOptions) (string, error) {
	// Batched writes (renderGuestScript) and the combined mkdir+read probe.
	if strings.HasPrefix(cmd, "set -e\n") {
		for _, line := range strings.Split(cmd, "\n") {
			if m := fakeWriteRe.FindStringSubmatch(line); m != nil {
				data, err := base64.StdEncoding.DecodeString(m[1])
				if err != nil {
					return "", err
				}
				f.files[m[2]] = string(data)
			}
		}
		return "", nil
	}
	if m := fakeReadRe.FindStringSubmatch(cmd); m != nil {
		if content, ok := f.files[m[1]]; ok {
			return autoContextExistsMarker + "\n" + content, nil
		}
		return autoContextMissingMarker + "\n", nil
	}
	fields := strings.Fields(cmd)
	switch {
	case strings.HasPrefix(cmd, "mkdir -p"):
		return "", nil
	case strings.HasPrefix(cmd, "test -f "):
		// test -f <path> && echo exists || echo missing
		if _, ok := f.files[fields[2]]; ok {
			return "exists\n", nil
		}
		return "missing\n", nil
	case strings.HasPrefix(cmd, "cat ") && strings.Contains(cmd, ">>"):
		// cat <staging> >> <dest> && rm -f <staging>
		staging, dest := fields[1], fields[3]
		f.files[dest] += f.files[staging]
		delete(f.files, staging)
		return "", nil
	case strings.HasPrefix(cmd, "cat "):
		// plain read: cat <path>
		return f.files[fields[1]], nil
	default:
		return "", nil
	}
}

func (f *fakeAutoCtxManager) CreateFile(path, content string) error {
	f.files[path] = content
	return nil
}

func (f *fakeAutoCtxManager) PushFile(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	f.files[dest] = string(data)
	return nil
}

func (f *fakeAutoCtxManager) Chown(_ string, _, _ int) error { return nil }

// fakeAutoCtxTool implements tool.ToolWithAutoContextFile with Claude's
// auto-context path. Only AutoContextFile is exercised by injectAutoContextFile;
// the embedded (nil) Tool interface covers the rest of the method set.
type fakeAutoCtxTool struct {
	tool.ToolWithAutoContextFile
}

func (fakeAutoCtxTool) AutoContextFile() string { return ".claude/CLAUDE.md" }

// TestInjectAutoContextFile_DoesNotAccumulateAcrossSessions reproduces #674:
// on a persistent container reused across sessions, the Coi sandbox context block
// (headed "# COI Sandbox Environment") is appended to ~/.claude/CLAUDE.md on every
// session instead of replacing the previous copy, so the file grows without bound
// (the reporter observed 16 copies / 108k chars, over Claude Code's 40k limit).
//
// Because "# COI Sandbox Environment" appears exactly once per rendered block, the
// number of occurrences equals the number of copies. Driving injectAutoContextFile
// across several sessions against one persistent home must leave exactly one copy.
// A host CLAUDE.md/AGENTS.md edited on Windows carries CRLF, so the coi block's
// markers end with \r. stripManagedAutoContext must still find and remove the
// block — otherwise a fresh copy is appended every session (the #674 growth bug).
// Pure-function test: the byte-exact fake-manager round-trip can't surface this.
func TestStripManagedAutoContext_CRLFMarkers(t *testing.T) {
	block := autoCtxBeginMarker + "\r\nsandbox body\r\n" + autoCtxEndMarker + "\r\n"
	input := "user prefix\r\n" + block + "user suffix\r\n"

	got := stripManagedAutoContext(input)

	if strings.Contains(got, autoCtxBeginMarker) || strings.Contains(got, autoCtxEndMarker) {
		t.Errorf("CRLF-delimited managed block should be stripped, got:\n%q", got)
	}
	if !strings.Contains(got, "user prefix") || !strings.Contains(got, "user suffix") {
		t.Errorf("user content must be preserved, got:\n%q", got)
	}
}

func TestInjectAutoContextFile_DoesNotAccumulateAcrossSessions(t *testing.T) {
	mgr := newFakeAutoCtxManager()
	acf := fakeAutoCtxTool{}
	homeDir := "/home/code"
	logger := func(string) {}

	content := tool.RenderContextFileContent(tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
		NetworkMode:   "restricted",
	})
	if !strings.Contains(content, "# COI Sandbox Environment") {
		t.Fatalf("precondition: rendered sandbox context should contain the header marker")
	}

	const sessions = 3
	for i := 0; i < sessions; i++ {
		if err := injectAutoContextFile(mgr, acf, content, homeDir, logger); err != nil {
			t.Fatalf("session %d: injectAutoContextFile failed: %v", i+1, err)
		}
	}

	claudeMD := mgr.files["/home/code/.claude/CLAUDE.md"]
	copies := strings.Count(claudeMD, "# COI Sandbox Environment")
	if copies != 1 {
		t.Errorf("#674: the Coi sandbox context block must appear exactly once in "+
			"~/.claude/CLAUDE.md after %d sessions, but found %d copies (%d chars) — it is being "+
			"appended on every session instead of replaced, so the file grows without bound.",
			sessions, copies, len(claudeMD))
	}
}

// TestInjectAutoContextFile_PreservesHostContent verifies that when the tool's
// auto-context file already contains user/host content (e.g. a CLAUDE.md copied
// from the host), injecting the sandbox context preserves that content and still
// keeps exactly one managed Coi block across repeated sessions.
func TestInjectAutoContextFile_PreservesHostContent(t *testing.T) {
	mgr := newFakeAutoCtxManager()
	acf := fakeAutoCtxTool{}
	homeDir := "/home/code"
	destPath := "/home/code/.claude/CLAUDE.md"
	logger := func(string) {}

	const userMarker = "MY-PROJECT-INSTRUCTIONS-DO-NOT-DROP"
	mgr.files[destPath] = "# My project rules\n\n" + userMarker + "\n"

	content := tool.RenderContextFileContent(tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
	})

	for i := 0; i < 3; i++ {
		if err := injectAutoContextFile(mgr, acf, content, homeDir, logger); err != nil {
			t.Fatalf("session %d: injectAutoContextFile failed: %v", i+1, err)
		}
	}

	got := mgr.files[destPath]
	if n := strings.Count(got, userMarker); n != 1 {
		t.Errorf("host/user content must be preserved exactly once, found %d occurrences of %q", n, userMarker)
	}
	if n := strings.Count(got, "# COI Sandbox Environment"); n != 1 {
		t.Errorf("expected exactly one Coi sandbox block alongside preserved content, found %d", n)
	}
}

// TestInjectAutoContextFile_HealsLegacyDuplicates covers the migration path for
// #674: a file already bloated by the pre-fix code (many unmarked copies joined
// by the old "# COI Sandbox Context" separator) must collapse to a single copy
// once the fixed injection runs, and stay there.
func TestInjectAutoContextFile_HealsLegacyDuplicates(t *testing.T) {
	mgr := newFakeAutoCtxManager()
	acf := fakeAutoCtxTool{}
	homeDir := "/home/code"
	destPath := "/home/code/.claude/CLAUDE.md"
	logger := func(string) {}

	content := tool.RenderContextFileContent(tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
		NetworkMode:   "restricted",
	})
	// Simulate the old (pre-#674) accumulation: three unmarked copies joined by
	// the legacy separator line.
	oldSep := "\n\n# COI Sandbox Context\n\n"
	mgr.files[destPath] = content + oldSep + content + oldSep + content

	for i := 0; i < 3; i++ {
		if err := injectAutoContextFile(mgr, acf, content, homeDir, logger); err != nil {
			t.Fatalf("session %d: injectAutoContextFile failed: %v", i+1, err)
		}
	}

	got := mgr.files[destPath]
	if n := strings.Count(got, "# COI Sandbox Environment"); n != 1 {
		t.Errorf("legacy duplicates must be healed to exactly one copy, found %d (%d chars)", n, len(got))
	}
}

// TestInjectAutoContextFile_HealsLegacyPreservingHostContent verifies the legacy
// cleanup keeps genuine user/host content that preceded the old coi copies.
func TestInjectAutoContextFile_HealsLegacyPreservingHostContent(t *testing.T) {
	mgr := newFakeAutoCtxManager()
	acf := fakeAutoCtxTool{}
	homeDir := "/home/code"
	destPath := "/home/code/.claude/CLAUDE.md"
	logger := func(string) {}

	content := tool.RenderContextFileContent(tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
	})
	const userMarker = "MY-PROJECT-RULES-KEEP-ME"
	host := "# My project rules\n\n" + userMarker + "\n"
	mgr.files[destPath] = host + "\n\n# COI Sandbox Context\n\n" + content + "\n\n# COI Sandbox Context\n\n" + content

	if err := injectAutoContextFile(mgr, acf, content, homeDir, logger); err != nil {
		t.Fatalf("injectAutoContextFile failed: %v", err)
	}

	got := mgr.files[destPath]
	if n := strings.Count(got, userMarker); n != 1 {
		t.Errorf("host content must be preserved exactly once, found %d occurrences of %q", n, userMarker)
	}
	if n := strings.Count(got, "# COI Sandbox Environment"); n != 1 {
		t.Errorf("legacy coi copies must be healed to one block, found %d", n)
	}
}

// TestInjectAutoContextFile_CodexAgentsMD verifies the codex wiring end-to-end
// with the REAL CodexTool: the managed block lands in ~/.codex/AGENTS.md
// (container-global — never the workspace AGENTS.md, which is on the host
// bind-mount), host-seeded AGENTS.md content is preserved, and repeated
// sessions keep exactly one copy of the block.
func TestInjectAutoContextFile_CodexAgentsMD(t *testing.T) {
	mgr := newFakeAutoCtxManager()
	codex, err := tool.Get("codex")
	if err != nil {
		t.Fatalf("Get(codex): %v", err)
	}
	acf, ok := codex.(tool.ToolWithAutoContextFile)
	if !ok {
		t.Fatal("CodexTool must implement ToolWithAutoContextFile")
	}
	homeDir := "/home/code"
	destPath := "/home/code/.codex/AGENTS.md"
	logger := func(string) {}

	const userMarker = "MY-GLOBAL-CODEX-RULES-KEEP-ME"
	mgr.files[destPath] = "# My codex instructions\n\n" + userMarker + "\n"

	content := tool.RenderContextFileContent(tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
		NetworkMode:   "restricted",
	})

	for i := 0; i < 3; i++ {
		if err := injectAutoContextFile(mgr, acf, content, homeDir, logger); err != nil {
			t.Fatalf("session %d: injectAutoContextFile failed: %v", i+1, err)
		}
	}

	got := mgr.files[destPath]
	if n := strings.Count(got, userMarker); n != 1 {
		t.Errorf("host AGENTS.md content must be preserved exactly once, found %d occurrences", n)
	}
	if n := strings.Count(got, "# COI Sandbox Environment"); n != 1 {
		t.Errorf("expected exactly one Coi sandbox block in ~/.codex/AGENTS.md, found %d", n)
	}
	// The workspace AGENTS.md must not be touched.
	if _, ok := mgr.files["/workspace/AGENTS.md"]; ok {
		t.Error("workspace AGENTS.md was written — the managed block must only go to ~/.codex/AGENTS.md")
	}
}

// TestInjectAutoContextFile_ContentContainingMarkerStaysIdempotent covers finding
// #1: when the injected content (e.g. a user-provided context_file) merely
// mentions the end-marker text inline — as a substring, not a standalone line —
// line-anchored matching must not treat it as a delimiter, so the block stays a
// single copy across sessions rather than being mis-parsed and duplicated.
func TestInjectAutoContextFile_ContentContainingMarkerStaysIdempotent(t *testing.T) {
	mgr := newFakeAutoCtxManager()
	acf := fakeAutoCtxTool{}
	homeDir := "/home/code"
	destPath := "/home/code/.claude/CLAUDE.md"
	logger := func(string) {}

	const sentinel = "CUSTOM-CONTEXT-SENTINEL"
	content := "# COI Sandbox Environment\n" + sentinel +
		"\nsee the " + autoCtxEndMarker + " marker inline\n"

	for i := 0; i < 3; i++ {
		if err := injectAutoContextFile(mgr, acf, content, homeDir, logger); err != nil {
			t.Fatalf("session %d: injectAutoContextFile failed: %v", i+1, err)
		}
	}

	got := mgr.files[destPath]
	if n := strings.Count(got, sentinel); n != 1 {
		t.Errorf("content mentioning the end marker inline must remain a single block, found %d copies (%d chars)", n, len(got))
	}
}
