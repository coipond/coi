package session

import (
	"errors"
	"strings"
	"testing"
)

func TestRawIdmapFailure_NamesSubuidCause(t *testing.T) {
	err := rawIdmapFailure(errors.New("exit status 1"), 411531718, "root:1000000:1000000000")
	msg := err.Error()

	for _, want := range []string{"host UID 411531718", "/etc/subuid", "root:1000000:1000000000", "unwritable"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	// ST1005 (staticcheck): error strings must not be capitalized or end with
	// punctuation/newline — the Build lane's golangci-lint enforces this.
	if strings.ContainsAny(msg, "\n") {
		t.Errorf("error string must not contain a newline:\n%q", msg)
	}
	if last := msg[len(msg)-1]; last == '.' || last == ':' || last == '!' {
		t.Errorf("error string must not end with punctuation, got %q", msg)
	}
	// The wrapped set error must be preserved for errors.Is/Unwrap.
	if !errors.Is(err, errors.Unwrap(err)) {
		t.Error("expected the raw.idmap set error to be wrapped with %w")
	}
}

func TestRawIdmapFailure_PlainWhenNotSubordinate(t *testing.T) {
	// Empty line → the host UID isn't subordinate → the generic message.
	msg := rawIdmapFailure(errors.New("boom"), 424242, "").Error()
	if strings.Contains(msg, "/etc/subuid") {
		t.Errorf("should not name /etc/subuid when the UID is not subordinate:\n%s", msg)
	}
	if !strings.Contains(msg, "unwritable") {
		t.Errorf("expected the generic unwritable-workspace message:\n%s", msg)
	}
}

// The actionable fix is emitted as a log line (not the error), so it may be
// multi-line and punctuated. It must carry the exact self-serve commands.
func TestRawIdmapGuidance_HasCopyPasteCommands(t *testing.T) {
	g := rawIdmapGuidance()
	for _, want := range []string{
		`echo "root:$(id -u):1" | sudo tee -a /etc/subuid /etc/subgid`,
		"sudo systemctl restart incus",
		"uid-1000", // container.CodeUID default
		"coi health",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("guidance missing %q:\n%s", want, g)
		}
	}
	// It must NOT suggest disable_shift (doesn't help this case).
	if strings.Contains(g, "disable_shift") {
		t.Errorf("guidance should not suggest disable_shift:\n%s", g)
	}
}
