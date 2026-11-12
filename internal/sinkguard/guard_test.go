package sinkguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// guardedPackages run (in whole or in part) while a `coi shell` session is
// interactively attached — the security monitors, the runtime-limit watchdog,
// and the network background IP refresher all execute in the coi process whose
// os.Stdout/os.Stderr are, at that point, the user's tmux terminal. They must
// therefore never write to a terminal sink; diagnostics go to the file-based
// SessionLogger (directly, via a callback, or via a package logger that routes
// to it). This is the regression guard for the issue #372 class: it fails CI if
// any such write is (re)introduced.
var guardedPackages = []string{
	"internal/monitor",
	"internal/nftmonitor",
	"internal/limits",
	"internal/network",
}

// forbidden tokens denote terminal sinks. "os.Stdout"/"os.Stderr" catch
// fmt.Fprint*(os.Stderr, …) and direct references while leaving buffer writes
// such as fmt.Fprintf(&sb, …) untouched. The fmt.Print*/log.* entries catch the
// global stdout/stderr helpers. The print/println builtins (which also write to
// stderr) are matched separately by builtinSinkRe below, since a bare "print("
// substring would false-match the legitimate "fmt.Fprint(".
var forbidden = []string{
	"os.Stdout",
	"os.Stderr",
	"fmt.Print(",
	"fmt.Printf(",
	"fmt.Println(",
	"log.Print(",
	"log.Printf(",
	"log.Println(",
	"log.Fatal",
	"log.Panic",
}

// builtinSinkRe matches the print/println builtins (which write to stderr) as
// standalone calls. The leading (^|[^\w.]) avoids false-matching fmt.Fprint( /
// strings.Sprint( (preceded by a letter) and a foo.print( method call (preceded
// by a dot).
var builtinSinkRe = regexp.MustCompile(`(^|[^\w.])print(ln)?\(`)

// allowMarker exempts a single source line. Use it ONLY for the documented
// stderr/standard-logger fallbacks that fire when no session logger is set
// (pre-attach / non-session CLI callers), never to silence a real leak.
const allowMarker = "terminal-sink-ok:"

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (go.mod)")
		}
		dir = parent
	}
}

// stringLitRe matches Go string literals — raw (`...`) and interpreted ("...",
// honoring \" escapes) — so a forbidden token that appears only inside a string
// (e.g. a log message mentioning os.Stderr, or a "//" inside a URL) is not
// treated as code.
var stringLitRe = regexp.MustCompile("`[^`]*`" + `|"(\\.|[^"\\])*"`)

// sanitizeLine strips string-literal contents and then a trailing line comment,
// leaving only code for the token/regex scan. Strings are removed BEFORE the
// comment so that a "//" inside a string literal does not prematurely truncate
// the line and hide a real sink after it.
func sanitizeLine(line string) string {
	line = stringLitRe.ReplaceAllString(line, "")
	if i := strings.Index(line, "//"); i >= 0 {
		line = line[:i]
	}
	return line
}

func TestSessionRuntimePackagesDoNotWriteToTerminal(t *testing.T) {
	root := repoRoot(t)
	var violations []string

	for _, pkg := range guardedPackages {
		dir := filepath.Join(root, filepath.FromSlash(pkg))
		// Walk the whole package tree (not just the top-level dir) so a sink in a
		// future sub-package under a guarded package is also caught.
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			for i, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, allowMarker) {
					continue
				}
				code := sanitizeLine(line)
				flagged := false
				for _, tok := range forbidden {
					if strings.Contains(code, tok) {
						violations = append(violations, formatViolation(rel, i+1, tok, line))
						flagged = true
						break
					}
				}
				if !flagged && builtinSinkRe.MatchString(code) {
					violations = append(violations, formatViolation(rel, i+1, "print/println builtin", line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", pkg, err)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("terminal-sink writes found in session-runtime packages (issue #372 class).\n"+
			"Route diagnostics to the SessionLogger instead; only the documented no-session "+
			"fallbacks may carry a %q comment.\n\n%s",
			allowMarker, strings.Join(violations, "\n"))
	}
}

func formatViolation(relPath string, line int, tok, src string) string {
	return relPath + ":" + strconv.Itoa(line) + ": " + tok + "  ->  " + strings.TrimSpace(src)
}

// TestBuiltinSinkRegex locks the print/println matcher: it must catch the
// builtins as standalone calls but not the legitimate fmt.Fprint*/Sprint* family
// or a .print( method call.
func TestBuiltinSinkRegex(t *testing.T) {
	shouldMatch := []string{
		`	println("leak")`,
		`	print("leak")`,
		`println(x)`,
		`	if true { println(y) }`,
	}
	shouldNotMatch := []string{
		`	fmt.Fprint(os.Stdout, "ok")`, // os.Stdout caught elsewhere; regex itself must not match
		`	fmt.Fprintln(&sb, "ok")`,     // buffer write
		`	s := strings.Sprint("ok")`,   // Sprint
		`	w.Fprintf("ok")`,             // Fprintf method-ish
		`	foo.print("method, not builtin")`,
	}
	for _, s := range shouldMatch {
		if !builtinSinkRe.MatchString(sanitizeLine(s)) {
			t.Errorf("expected builtin match for: %q", s)
		}
	}
	for _, s := range shouldNotMatch {
		if builtinSinkRe.MatchString(sanitizeLine(s)) {
			t.Errorf("unexpected builtin match for: %q", s)
		}
	}
}

// TestSanitizeLine locks that string literals and comments are stripped before
// scanning: a sink token inside a string/comment must NOT be flagged (false
// positive), but a real sink on a line whose string contains "//" must STILL be
// seen (false negative).
func TestSanitizeLine(t *testing.T) {
	// A forbidden token only inside a string or comment -> removed (not flagged).
	notSink := []string{
		`	errMsg := "writes to os.Stderr on failure"`,
		`	url := "https://example.com/x"`,
		`	doThing() // see os.Stderr docs`,
		"\ts := `raw with os.Stdout inside`",
		`	msg := "use fmt.Println here"`,
	}
	for _, s := range notSink {
		code := sanitizeLine(s)
		for _, tok := range forbidden {
			if strings.Contains(code, tok) {
				t.Errorf("false positive: %q matched %q after sanitize -> %q", s, tok, code)
			}
		}
		if builtinSinkRe.MatchString(code) {
			t.Errorf("false positive (builtin): %q -> %q", s, code)
		}
	}

	// A real sink on a line whose STRING contains "//" must survive sanitize.
	realSink := `	u := "http://x"; fmt.Fprintln(os.Stderr, u)`
	if !strings.Contains(sanitizeLine(realSink), "os.Stderr") {
		t.Errorf("false negative: real os.Stderr sink hidden by // inside string: %q -> %q",
			realSink, sanitizeLine(realSink))
	}
}
