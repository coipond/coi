package image

import "testing"

func TestAgentEnv(t *testing.T) {
	if env := agentEnv(nil); env != nil {
		t.Errorf("nil agents should yield nil env (default agent set), got %v", env)
	}
	if env := agentEnv([]string{}); env != nil {
		t.Errorf("empty agents should yield nil env (default agent set), got %v", env)
	}
	env := agentEnv([]string{"claude", "pi"})
	if env["COI_AGENTS"] != "claude,pi" {
		t.Errorf("COI_AGENTS = %q, want %q", env["COI_AGENTS"], "claude,pi")
	}
}

// Finding 4 (Env wiring): prove the builder actually threads the agent selection
// into the exec options used to run build.sh — i.e. runBuildScriptResolved does not
// silently drop the Env. Testable without launching a container.
func TestBuildScriptExecOpts(t *testing.T) {
	t.Setenv("COI_APT_MIRROR", "") // isolate from the ambient env (CI sets it)

	// Selection present -> COI_AGENTS delivered to the script.
	b := NewBuilder(BuildOptions{Agents: []string{"claude", "pi"}})
	opts := b.buildScriptExecOpts()
	if opts.Env["COI_AGENTS"] != "claude,pi" {
		t.Errorf("exec opts COI_AGENTS = %q, want %q", opts.Env["COI_AGENTS"], "claude,pi")
	}
	if opts.Capture {
		t.Error("build script exec should stream (Capture=false), not capture")
	}

	// No selection and no mirror -> nil Env, so build.sh keeps its defaults.
	b = NewBuilder(BuildOptions{})
	if opts := b.buildScriptExecOpts(); opts.Env != nil {
		t.Errorf("empty agents + no mirror should leave Env nil, got %v", opts.Env)
	}
}

// COI_APT_MIRROR must be forwarded into the build container's env when set
// (CI points it at a fast mirror), and absent when unset (local builds keep
// the stock mirrors), independent of the agent selection.
func TestBuildScriptEnv_AptMirror(t *testing.T) {
	t.Setenv("COI_APT_MIRROR", "http://azure.archive.ubuntu.com/ubuntu")
	env := buildScriptEnv(nil, false)
	if env["COI_APT_MIRROR"] != "http://azure.archive.ubuntu.com/ubuntu" {
		t.Errorf("COI_APT_MIRROR not forwarded, got %v", env)
	}
	// Forwarded alongside an agent selection, not instead of it.
	env = buildScriptEnv([]string{"claude"}, false)
	if env["COI_AGENTS"] != "claude" || env["COI_APT_MIRROR"] == "" {
		t.Errorf("expected both COI_AGENTS and COI_APT_MIRROR, got %v", env)
	}

	t.Setenv("COI_APT_MIRROR", "")
	if env := buildScriptEnv(nil, false); env != nil {
		t.Errorf("unset mirror + no agents should yield nil env, got %v", env)
	}
}

// [container.build] cloud_init = true reaches build.sh as COI_CLOUD_INIT=1;
// the default passes nothing (build.sh then disables cloud-init).
func TestBuildScriptEnv_CloudInit(t *testing.T) {
	t.Setenv("COI_APT_MIRROR", "")
	if env := buildScriptEnv(nil, true); env["COI_CLOUD_INIT"] != "1" {
		t.Errorf("cloud_init=true must set COI_CLOUD_INIT=1, got %v", env)
	}
	if env := buildScriptEnv(nil, false); env != nil {
		t.Errorf("default must pass no env, got %v", env)
	}
}
