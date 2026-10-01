package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/tool"
)

// writeBuildScript materializes the embedded build.sh so bash/sed can read it.
func writeBuildScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "build.sh")
	if err := os.WriteFile(path, embeddedCoiBuildScript, 0o644); err != nil {
		t.Fatalf("write build.sh: %v", err)
	}
	return path
}

// dispatchAgents sources the REAL install_selected_agents from build.sh and runs it
// with the given COI_AGENTS value (nil = unset). The per-agent installer functions are
// intentionally NOT defined; a command-not-found handler reports which installer each
// agent maps to. This makes the check behavior-true and immune to build.sh formatting
// (case arms on one line or wrapped, default literal quoted or not), and it needs no
// hardcoded knowledge of installer names — so it stays honest when the registry grows.
// A truncated/garbled function fails to `source` and surfaces loudly rather than
// silently passing. Returns the installer functions invoked, in order, plus WARNINGs.
func dispatchAgents(t *testing.T, scriptPath string, coiAgents *string) (installers, warnings []string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	const driver = `set -uo pipefail
command_not_found_handle() { echo "INSTALLER:$1"; return 0; }
log() { case "$*" in *WARNING*) echo "WARN:$*" ;; esac; }
source <(sed -n '/^install_selected_agents()/,/^}/p' "$1") || { echo "SOURCE_FAILED"; exit 3; }
install_selected_agents`
	cmd := exec.Command("bash", "-c", driver, "bash", scriptPath)

	env := make([]string, 0, len(os.Environ())+1)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "COI_AGENTS=") {
			env = append(env, e)
		}
	}
	if coiAgents != nil {
		env = append(env, "COI_AGENTS="+*coiAgents)
	}
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dispatch failed (%v):\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if s, ok := strings.CutPrefix(line, "INSTALLER:"); ok {
			installers = append(installers, s)
		} else if s, ok := strings.CutPrefix(line, "WARN:"); ok {
			warnings = append(warnings, s)
		}
	}
	return installers, warnings
}

// Finding 3 (registry <-> build.sh drift): the agent set is encoded in build.sh (the
// install_selected_agents case arms and the ${COI_AGENTS:-...} default) parallel to the
// Go tool registry, with nothing keeping them in sync — a newly-registered agent could
// pass host-side validateBuildAgents yet hit build.sh's `*` arm and install nothing
// (silent exit-127). This drives the REAL dispatch so it fails the moment the registry
// and build.sh diverge, and — unlike a regex scan — cannot be broken by reformatting.
func TestBuildScriptDispatchMatchesRegistry(t *testing.T) {
	path := writeBuildScript(t)
	supported := tool.ListSupported()
	if len(supported) == 0 {
		t.Fatal("tool.ListSupported() is empty")
	}

	// Unset COI_AGENTS must dispatch to exactly the installers that an explicit
	// COI_AGENTS=tool.DefaultBuildAgents() run dispatches to — i.e. the
	// ${COI_AGENTS:-...} default lists exactly the Go-side default set (a subset
	// of the registry: opt-in agents like codex are excluded, #698). Comparing
	// the two dispatch runs checks MEMBERSHIP AND ORDER, not just count, so a
	// same-length drift (e.g. build.sh default gaining codex but dropping pi
	// while DefaultBuildAgents() is unchanged) fails red — that drift would make
	// prepareBuildAgents' footgun warning reason about a default set the image
	// doesn't actually install.
	defaults := tool.DefaultBuildAgents()
	installers, _ := dispatchAgents(t, path, nil)
	explicit := strings.Join(defaults, " ")
	wantInstallers, _ := dispatchAgents(t, path, &explicit)
	if len(wantInstallers) != len(defaults) {
		t.Errorf("explicit default agents %v invoked %d installers %v, want one per agent",
			defaults, len(wantInstallers), wantInstallers)
	}
	if !slices.Equal(installers, wantInstallers) {
		t.Errorf("unset COI_AGENTS invoked installers %v, but tool.DefaultBuildAgents()=%v dispatches %v; "+
			"the ${COI_AGENTS:-...} default must list exactly tool.DefaultBuildAgents()",
			installers, defaults, wantInstallers)
	}

	// Every supported agent must dispatch to exactly one installer (a case arm exists).
	for _, a := range supported {
		got, warns := dispatchAgents(t, path, &a)
		if len(got) != 1 || len(warns) != 0 {
			t.Errorf("agent %q dispatched to installers %v (warnings %v); want exactly one and "+
				"no warning — build.sh is missing a case arm for a registered agent", a, got, warns)
		}
	}

	// An unsupported name installs nothing and warns (the defense-in-depth `*` arm).
	bogus := "definitely-not-an-agent"
	got, warns := dispatchAgents(t, path, &bogus)
	if len(got) != 0 {
		t.Errorf("unsupported agent invoked installers %v, want none", got)
	}
	if len(warns) == 0 {
		t.Error("unsupported agent should emit a WARNING, got none")
	}
}

// extractShellFunc returns the body of a `name() { ... }` function from build.sh,
// assuming the closing brace sits at column 0 (the style build.sh uses). Callers must
// guard against silent truncation (a stray column-0 `\n}` mid-body) by asserting a
// sentinel from the tail of the function is present in the result.
func extractShellFunc(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, name+"() {")
	if start < 0 {
		t.Fatalf("build.sh: function %s() not found", name)
	}
	rest := script[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("build.sh: could not find end of %s()", name)
	}
	return rest[:end]
}

// stripShellComments removes `#`-to-end-of-line comments so a comment that merely
// mentions an installer name cannot false-fail the dispatch check. Deliberately simple:
// build.sh's main() has no `#` inside string literals, so cutting at the first `#` on
// each line is sufficient and safe.
func stripShellComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// Finding 4 (call-site coverage): the hermetic bash test sources only
// install_selected_agents, so a revert of main() to the old unconditional
// install_claude_cli/install_opencode/install_pi calls would leave every test green
// while the selector goes dead. Assert main() dispatches through install_selected_agents
// and never calls the per-agent installers directly. Comments are stripped first (so a
// comment mentioning an installer can't false-fail) and a tail sentinel guards against
// extracting a truncated main() body.
func TestBuildScriptMainDispatchesThroughSelector(t *testing.T) {
	main := extractShellFunc(t, string(embeddedCoiBuildScript), "main")
	if !strings.Contains(main, "cleanup") {
		t.Fatalf("extracted main() looks truncated (missing the trailing 'cleanup' call):\n%s", main)
	}
	body := stripShellComments(main)

	if !strings.Contains(body, "install_selected_agents") {
		t.Error("main() must call install_selected_agents (agent selection is bypassed otherwise)")
	}
	for _, direct := range []string{"install_claude_cli", "install_opencode", "install_pi"} {
		if strings.Contains(body, direct) {
			t.Errorf("main() calls %s directly; per-agent installers must only be reached via "+
				"install_selected_agents so COI_AGENTS is honored", direct)
		}
	}
}
