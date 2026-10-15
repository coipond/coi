package cli

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// applyConfigEnv reports each variable under the layer that actually set it:
// env_commands over forward_env over [defaults] environment. A forward_env name
// unset on the host is skipped, so a config value under the same name stays
// "set by config", and a name only present for another reason (TZ, HOME) is not
// claimed as forwarded.
func TestApplyConfigEnv_Sources(t *testing.T) {
	t.Setenv("COI_TEST_FWD", "host")
	t.Setenv("COI_TEST_BOTH", "host")
	a := &App{cfg: &config.Config{Defaults: config.DefaultsConfig{
		Environment: map[string]string{"STATIC": "v", "COI_TEST_UNSET": "cfg", "COI_TEST_BOTH": "cfg", "TOKEN": "cfg"},
		ForwardEnv:  []string{"COI_TEST_FWD", "COI_TEST_UNSET", "COI_TEST_BOTH", "COI_TEST_NOT_ON_HOST_TZ"},
		EnvCommands: map[string]string{"TOKEN": "printf minted"},
	}}}
	env := map[string]string{"HOME": "/home/code", "COI_TEST_NOT_ON_HOST_TZ": "Europe/Warsaw"}
	g, err := a.applyConfigEnv(env)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(g.Minted, ","); got != "TOKEN" {
		t.Errorf("Minted = %q, want TOKEN", got)
	}
	if got := strings.Join(g.FromHost, ","); got != "COI_TEST_BOTH,COI_TEST_FWD" {
		t.Errorf("FromHost = %q, want COI_TEST_BOTH,COI_TEST_FWD", got)
	}
	if got := strings.Join(g.Configured, ","); got != "COI_TEST_UNSET,STATIC" {
		t.Errorf("Configured = %q, want COI_TEST_UNSET,STATIC", got)
	}
	if env["TOKEN"] != "minted" || env["COI_TEST_BOTH"] != "host" || env["COI_TEST_UNSET"] != "cfg" {
		t.Errorf("env values = %v", env)
	}
}
