package cli

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// envGrants names only the config-sourced variables that made it into the
// container env, each under the source that won: env_commands over forward_env
// over [defaults] environment.
func TestEnvGrants_SourcesAndPrecedence(t *testing.T) {
	a := &App{cfg: &config.Config{Defaults: config.DefaultsConfig{
		Environment: map[string]string{"STATIC": "v", "SHARED": "v", "TOKEN": "v"},
		ForwardEnv:  []string{"GH_TOKEN", "UNSET_ON_HOST", "SHARED"},
		EnvCommands: map[string]string{"TOKEN": "mint"},
	}}}
	containerEnv := map[string]string{
		"HOME": "/home/code", "STATIC": "v", "SHARED": "host", "TOKEN": "minted", "GH_TOKEN": "x",
	}
	g := a.envGrants(containerEnv)

	if got := strings.Join(g.Minted, ","); got != "TOKEN" {
		t.Errorf("Minted = %q, want TOKEN", got)
	}
	if got := strings.Join(g.FromHost, ","); got != "GH_TOKEN,SHARED" {
		t.Errorf("FromHost = %q, want GH_TOKEN,SHARED (UNSET_ON_HOST absent)", got)
	}
	if got := strings.Join(g.Configured, ","); got != "STATIC" {
		t.Errorf("Configured = %q, want STATIC", got)
	}
}
