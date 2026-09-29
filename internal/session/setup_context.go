package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mensfeld/code-on-incus/internal/container"
	"github.com/mensfeld/code-on-incus/internal/tool"
)

// injectContextFile creates ~/SANDBOX_CONTEXT.md inside the container.
// If customPath is provided, it reads the file from the host and uses its content.
// Otherwise, it renders the default embedded template with dynamic environment info.
func injectContextFile(mgr container.ContainerManager, info tool.ContextInfo, customPath, homeDir string, logger func(string)) error {
	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.md")

	var content string
	if customPath != "" {
		data, err := os.ReadFile(customPath)
		if err != nil {
			return fmt.Errorf("failed to read custom context file %s: %w", customPath, err)
		}
		content = string(data)
		logger(fmt.Sprintf("Using custom context file: %s", customPath))
	} else {
		content = tool.RenderContextFileContent(info)
		logger("Injecting default sandbox context file")
	}

	// Create the file
	if err := mgr.CreateFile(destPath, content); err != nil {
		return fmt.Errorf("failed to create context file %s: %w", destPath, err)
	}

	// Fix ownership if running as non-root user
	if homeDir != "/root" {
		if err := mgr.Chown(destPath, container.CodeUID, container.CodeUID); err != nil {
			return fmt.Errorf("failed to set context file ownership: %w", err)
		}
	}

	logger(fmt.Sprintf("Context file injected at %s", destPath))
	return nil
}

// injectContextJSONFile creates ~/SANDBOX_CONTEXT.json inside the container: the
// machine-readable companion to SANDBOX_CONTEXT.md for programmatic consumers
// (#705). If customPath is provided ([tool] context_json_file), that host file
// is injected verbatim; otherwise the JSON is rendered from the resolved
// ContextInfo (the real sandbox facts). Reuses the same container write path as
// injectContextFile.
func injectContextJSONFile(mgr container.ContainerManager, info tool.ContextInfo, customPath, homeDir string, logger func(string)) error {
	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.json")

	content, err := resolveContextJSON(customPath, info, logger)
	if err != nil {
		return err
	}

	if err := mgr.CreateFile(destPath, content); err != nil {
		return fmt.Errorf("failed to create context JSON file %s: %w", destPath, err)
	}

	// Fix ownership if running as non-root user (mirrors injectContextFile).
	if homeDir != "/root" {
		if err := mgr.Chown(destPath, container.CodeUID, container.CodeUID); err != nil {
			return fmt.Errorf("failed to set context JSON file ownership: %w", err)
		}
	}

	logger(fmt.Sprintf("Context JSON file injected at %s", destPath))
	return nil
}

// resolveContextJSON returns the content for ~/SANDBOX_CONTEXT.json. A custom
// file ([tool] context_json_file) is injected verbatim ONLY if it is actually
// valid JSON — that file exists for programmatic consumers, so a malformed or
// unreadable custom file (typo, truncated write, wrong path) would break exactly
// them. On any problem it warns and falls back to the generated JSON, so the
// file is always present and always valid. Only the host read is I/O; the rest
// is pure, so the fallback logic is unit-testable.
func resolveContextJSON(customPath string, info tool.ContextInfo, logger func(string)) (string, error) {
	if customPath != "" {
		if data, err := os.ReadFile(customPath); err != nil {
			logger(fmt.Sprintf("Warning: could not read custom context JSON file %s (%v); using the generated SANDBOX_CONTEXT.json", customPath, err))
		} else if !json.Valid(data) {
			logger(fmt.Sprintf("Warning: custom context JSON file %s is not valid JSON; using the generated SANDBOX_CONTEXT.json", customPath))
		} else {
			logger(fmt.Sprintf("Using custom context JSON file: %s", customPath))
			return string(data), nil
		}
	}
	rendered, err := tool.RenderContextFileJSON(info)
	if err != nil {
		return "", fmt.Errorf("failed to render context JSON: %w", err)
	}
	return rendered, nil
}

// resolveContextContent returns the sandbox context content string.
// If customPath is provided, it reads the file from the host; otherwise it
// renders the default embedded template. This is used both for ~/SANDBOX_CONTEXT.md
// and for auto-context injection into tool-native files.
func resolveContextContent(info tool.ContextInfo, customPath string, logger func(string)) string {
	if customPath != "" {
		data, err := os.ReadFile(customPath)
		if err != nil {
			logger(fmt.Sprintf("Warning: Failed to read custom context file %s: %v", customPath, err))
			return ""
		}
		return string(data)
	}
	return tool.RenderContextFileContent(info)
}

// Markers delimiting the coi-managed sandbox context block inside the tool's
// auto-load file. The block is rewritten (not appended) every session, so the
// file never accumulates duplicate copies (#674). Anything outside the markers
// (e.g. a CLAUDE.md copied from the host) is preserved. Matching is line-anchored
// (a marker must be a whole line), so a marker string appearing mid-content — for
// example inside a user-provided context_file — cannot be mistaken for a real
// delimiter.
const (
	autoCtxBeginMarker = "# BEGIN COI Sandbox Context (managed by coi - do not edit this block)"
	autoCtxEndMarker   = "# END COI Sandbox Context (managed by coi)"

	// legacyAutoCtxSeparator is the bare separator line the pre-#674 code wrote
	// between appended copies (which had no BEGIN/END markers). It is coi-exclusive,
	// so it can be used to recognize and clean up old accumulated copies.
	legacyAutoCtxSeparator = "# COI Sandbox Context"

	// coiContextHeader is the first line of a rendered sandbox context block, and
	// coiContextFingerprint is a stable, distinctive substring from its body. A
	// segment matching both is a coi-generated block (not user content).
	// The fingerprint is deliberately just "Code on Incus" (no "(COI)"/"(Coi)"
	// suffix) so it keeps matching blocks written by BOTH the pre-rebrand coi
	// ("Code on Incus (COI)") and the current one ("Coi (Code on Incus)") — a
	// persistent container upgraded across the rename must still have its old
	// managed block recognized and replaced, not duplicated (#674).
	coiContextHeader      = "# COI Sandbox Environment"
	coiContextFingerprint = "Code on Incus"
)

// lineIndex returns the index of the first element of lines at or after `from`
// that equals target, or -1. Used for line-anchored marker matching.
func lineIndex(lines []string, from int, target string) int {
	for i := from; i < len(lines); i++ {
		// Tolerate a trailing CR: a host CLAUDE.md/AGENTS.md edited and saved on
		// Windows converts the coi block's markers to CRLF, and an exact match
		// would then miss the old block and re-append a new one every session
		// (the #674 growth bug). Match on the content, keep the bytes.
		if strings.TrimRight(lines[i], "\r") == target {
			return i
		}
	}
	return -1
}

// stripManagedAutoContext removes a previously coi-written managed block (the
// whole-line autoCtxBeginMarker through the whole-line autoCtxEndMarker,
// inclusive) from s, so a fresh block can replace it instead of stacking on top
// of it. Content outside the block is returned untouched. If the begin marker is
// present but no end marker follows (a truncated/hand-mangled block), everything
// from the begin marker on is dropped rather than left half-parsed.
func stripManagedAutoContext(s string) string {
	lines := strings.Split(s, "\n")
	begin := lineIndex(lines, 0, autoCtxBeginMarker)
	if begin == -1 {
		return s
	}
	end := lineIndex(lines, begin+1, autoCtxEndMarker)
	if end == -1 {
		return strings.Join(lines[:begin], "\n")
	}
	kept := append(append([]string{}, lines[:begin]...), lines[end+1:]...)
	return strings.Join(kept, "\n")
}

// isRenderedCOIBlock reports whether s (ignoring surrounding whitespace) is a
// coi-generated sandbox context block rather than user content: it must start
// with the sandbox header and carry the distinctive body fingerprint.
func isRenderedCOIBlock(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, coiContextHeader) && strings.Contains(t, coiContextFingerprint)
}

// stripLegacyAutoContext removes sandbox blocks written by the pre-#674 code,
// which appended copies separated by a bare "# COI Sandbox Context" line and had
// no BEGIN/END markers. It splits on that (coi-exclusive) separator line and
// drops every segment that is a rendered coi block, keeping genuine user/host
// content. This heals a file that already accumulated many copies (a reporter
// hit 16 / 108k chars) — after the current injection re-adds one managed block,
// the file collapses to a single copy plus any real user content.
//
// Caveat: content a user manually inserted *inside or immediately after* a
// legacy coi copy (so that the copy+note reads as one coi-looking segment) is
// dropped with that copy. That is rare, and preferable to leaving the file over
// the tool's size limit.
func stripLegacyAutoContext(s string) string {
	if !strings.Contains(s, coiContextHeader) {
		return s // no coi-generated content to clean up
	}
	var segments [][]string
	cur := []string{}
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimRight(ln, "\r") == legacyAutoCtxSeparator {
			segments = append(segments, cur)
			cur = nil
			continue
		}
		cur = append(cur, ln)
	}
	segments = append(segments, cur)

	var kept []string
	for _, seg := range segments {
		segStr := strings.Join(seg, "\n")
		if strings.TrimSpace(segStr) == "" || isRenderedCOIBlock(segStr) {
			continue
		}
		kept = append(kept, strings.TrimRight(segStr, "\n"))
	}
	return strings.Join(kept, "\n\n")
}

// injectAutoContextFile writes sandbox context into the tool's native auto-load
// file (e.g., ~/.claude/CLAUDE.md) as a single coi-managed block delimited by
// autoCtxBeginMarker/autoCtxEndMarker. If the file already exists (e.g. copied
// from host, or left over from a previous session on a persistent container), any
// prior managed block is stripped and a fresh one is written in its place, so the
// file does not grow a new copy every session (#674). Non-managed content in the
// file is preserved.
func injectAutoContextFile(mgr container.ContainerManager, acf tool.ToolWithAutoContextFile, contextContent, homeDir string, logger func(string)) error {
	relPath := acf.AutoContextFile()
	destPath := filepath.Join(homeDir, relPath)
	destDir := filepath.Dir(destPath)

	// Ensure parent directory exists
	mkdirCmd := fmt.Sprintf("mkdir -p %s", destDir)
	if _, err := mgr.ExecCommand(mkdirCmd, container.ExecCommandOptions{Capture: true}); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", relPath, err)
	}

	managedBlock := autoCtxBeginMarker + "\n" + contextContent + "\n" + autoCtxEndMarker + "\n"

	// Check if the file already exists in the container (e.g., host's CLAUDE.md was
	// copied, or the container is persistent and a prior session already wrote one).
	checkCmd := fmt.Sprintf("test -f %s && echo exists || echo missing", destPath)
	checkResult, err := mgr.ExecCommand(checkCmd, container.ExecCommandOptions{Capture: true})

	var newContent string
	if err == nil && strings.TrimSpace(checkResult) == "exists" {
		// Read the current file, drop any prior managed block AND any old-format
		// copies from before #674, then re-attach a single fresh block. This keeps
		// exactly one always-current copy while preserving any user/host content,
		// instead of appending a new copy every session (#674) — and heals files
		// that already accumulated many copies under the old code.
		existing, readErr := mgr.ExecCommand(fmt.Sprintf("cat %s", destPath), container.ExecCommandOptions{Capture: true})
		if readErr != nil {
			return fmt.Errorf("failed to read %s: %w", relPath, readErr)
		}
		preserved := strings.TrimRight(stripLegacyAutoContext(stripManagedAutoContext(existing)), "\n")
		if preserved == "" {
			logger(fmt.Sprintf("Refreshing sandbox context in %s", relPath))
			newContent = managedBlock
		} else {
			logger(fmt.Sprintf("Refreshing sandbox context in %s (preserving existing content)", relPath))
			newContent = preserved + "\n\n" + managedBlock
		}
	} else {
		logger(fmt.Sprintf("Creating %s with sandbox context", relPath))
		newContent = managedBlock
	}

	// Overwrite the file with the reconciled content (single managed block).
	if err := mgr.CreateFile(destPath, newContent); err != nil {
		return fmt.Errorf("failed to write %s: %w", relPath, err)
	}

	// Fix ownership if running as non-root user
	if homeDir != "/root" {
		if err := mgr.Chown(destPath, container.CodeUID, container.CodeUID); err != nil {
			return fmt.Errorf("failed to set %s ownership: %w", relPath, err)
		}
	}

	logger(fmt.Sprintf("Auto-context injected at %s", destPath))
	return nil
}
