package session

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// createWithOwnerCall records one CreateFileWithOwner invocation.
type createWithOwnerCall struct {
	path    string
	content string
	uid     int
	gid     int
	mode    string
}

// managedSettingsRecorder implements the ExecCommand and CreateFileWithOwner
// methods SetupClaudeManagedSettings uses; the embedded interface panics on
// anything else so unexpected calls fail loudly.
type managedSettingsRecorder struct {
	container.ContainerManager
	commands []string
	creates  []createWithOwnerCall
	// execErr, if set, decides whether a given in-container command fails.
	execErr func(command string) error
	// createErr, if set, fails every CreateFileWithOwner call.
	createErr error
}

func (r *managedSettingsRecorder) ExecCommand(command string, _ container.ExecCommandOptions) (string, error) {
	r.commands = append(r.commands, command)
	if r.execErr != nil {
		if err := r.execErr(command); err != nil {
			return "", err
		}
	}
	// A batched guest script: its file writes count as pushes.
	if writes := decodeGuestWrites(command); len(writes) > 0 {
		if r.createErr != nil {
			return "", r.createErr
		}
		r.creates = append(r.creates, writes...)
	}
	return "", nil
}

var guestWriteRe = regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]*)' \| base64 -d > '[^']*' && chown (\d+):(\d+) '[^']*' && chmod '([0-7]+)' '[^']*' && mv -f '[^']*' '([^']*)'`)

// decodeGuestWrites recovers the file writes from a renderGuestScript script.
func decodeGuestWrites(script string) []createWithOwnerCall {
	var out []createWithOwnerCall
	for _, m := range guestWriteRe.FindAllStringSubmatch(script, -1) {
		content, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			continue
		}
		uid, _ := strconv.Atoi(m[2])
		gid, _ := strconv.Atoi(m[3])
		out = append(out, createWithOwnerCall{path: m[5], content: string(content), uid: uid, gid: gid, mode: m[4]})
	}
	return out
}

func (r *managedSettingsRecorder) CreateFileWithOwner(path, content string, uid, gid int, mode string) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.creates = append(r.creates, createWithOwnerCall{path: path, content: content, uid: uid, gid: gid, mode: mode})
	return nil
}

// A plain CreateFile push inherits the host temp file's mode (0600) and UID,
// which the container code user cannot read when the host UID differs from it
// (macOS 501, CI runners 1001) — Claude Code then fails OAuth with EACCES on
// the policy file. Setup must push the file root-owned and world-readable in
// one operation so no window or failure path leaves it unreadable.
func TestSetupClaudeManagedSettingsCreatesRootOwnedWorldReadableFile(t *testing.T) {
	rec := &managedSettingsRecorder{}

	SetupClaudeManagedSettings(rec, true, true, func(msg string) { t.Log(msg) })

	if len(rec.creates) != 1 {
		t.Fatalf("expected exactly one CreateFileWithOwner call, got %v", rec.creates)
	}
	got := rec.creates[0]
	if got.path != "/etc/claude-code/managed-settings.json" {
		t.Errorf("path = %q, want /etc/claude-code/managed-settings.json", got.path)
	}
	if !strings.Contains(got.content, "disableAutoMode") {
		t.Errorf("unexpected managed settings content: %s", got.content)
	}
	if got.uid != 0 || got.gid != 0 {
		t.Errorf("owner = %d:%d, want 0:0", got.uid, got.gid)
	}
	if got.mode != "0644" {
		t.Errorf("mode = %q, want 0644", got.mode)
	}
}

// shouldSuppressClaudeAutoMode gates whether the managed-settings policy that
// strips auto mode gets written. It must fire for Claude under the default
// (bypass) mode and NOT under interactive, where the user owns the per-session
// auto-mode choice (#764); non-Claude tools never get the policy.
func TestShouldSuppressClaudeAutoMode(t *testing.T) {
	cases := []struct {
		name           string
		toolName       string
		permissionMode string
		want           bool
	}{
		{"claude default/bypass suppresses", "claude", "", true},
		{"claude explicit bypass suppresses", "claude", "bypass", true},
		{"claude interactive does not suppress", "claude", "interactive", false},
		{"non-claude bypass never suppresses", "codex", "bypass", false},
		{"non-claude interactive never suppresses", "codex", "interactive", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldSuppressClaudeAutoMode(tc.toolName, tc.permissionMode); got != tc.want {
				t.Errorf("shouldSuppressClaudeAutoMode(%q, %q) = %v, want %v", tc.toolName, tc.permissionMode, got, tc.want)
			}
		})
	}
}

func TestSetupClaudeManagedSettingsWarnsWhenWriteFails(t *testing.T) {
	rec := &managedSettingsRecorder{createErr: errors.New("push failed")}
	var logs []string

	SetupClaudeManagedSettings(rec, true, false, func(msg string) { logs = append(logs, msg) })

	if len(logs) == 0 {
		t.Fatal("expected a warning log when writing managed settings fails")
	}
}

func TestSetupClaudeManagedSettingsSkipsWriteWhenMkdirFails(t *testing.T) {
	rec := &managedSettingsRecorder{execErr: func(cmd string) error {
		if strings.Contains(cmd, "mkdir") {
			return errors.New("mkdir failed")
		}
		return nil
	}}
	var logs []string

	SetupClaudeManagedSettings(rec, true, false, func(msg string) { logs = append(logs, msg) })

	if len(rec.creates) != 0 {
		t.Fatalf("no file should be written after mkdir failure, got %v", rec.creates)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "mkdir failed") {
		t.Fatalf("expected exactly one warning carrying the mkdir failure, got %v", logs)
	}
}
