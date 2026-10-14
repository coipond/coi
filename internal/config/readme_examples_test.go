package config

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/BurntSushi/toml"
	coischema "github.com/coipond/coi/schema"
)

var tomlFence = regexp.MustCompile("(?s)```toml\n(.*?)```")

// Every ```toml example in the README must load as written, either as a
// config.toml or as a profile config.toml. The global config ignores unknown
// keys, so a stale example (e.g. `[limits] memory = "8GiB"`, #890) would
// otherwise only surface when a user copies it.
func TestREADMETomlExamplesLoad(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := tomlFence.FindAllStringSubmatch(string(data), -1)
	if len(blocks) == 0 {
		t.Fatal("no ```toml blocks found in README.md")
	}
	for i, b := range blocks {
		src := b[1]
		cfgErr := strictDecode(src, &Config{})
		profErr := strictDecode(src, &ProfileConfig{})
		if profErr == nil {
			var raw map[string]any
			if _, err := toml.Decode(src, &raw); err != nil {
				profErr = err
			} else {
				profErr = coischema.ValidateProfileMap(raw)
			}
		}
		if cfgErr != nil && profErr != nil {
			t.Errorf("README toml block %d does not load:\n  as config: %v\n  as profile: %v\n%s", i+1, cfgErr, profErr, src)
		}
	}
}

func strictDecode(src string, v any) error {
	md, err := toml.Decode(src, v)
	if err != nil {
		return err
	}
	if u := md.Undecoded(); len(u) > 0 {
		return fmt.Errorf("unknown keys: %v", u)
	}
	return nil
}

// The coi-profile agent skill teaches agents to write profiles, so every
// ```toml example in it must be a valid profile config.toml.
func TestProfileSkillTomlExamplesValidate(t *testing.T) {
	data, err := os.ReadFile("../../skills/coi-profile/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := tomlFence.FindAllStringSubmatch(string(data), -1)
	if len(blocks) == 0 {
		t.Fatal("no ```toml blocks found in skills/coi-profile/SKILL.md")
	}
	for i, b := range blocks {
		src := b[1]
		err := strictDecode(src, &ProfileConfig{})
		if err == nil {
			var raw map[string]any
			if _, err = toml.Decode(src, &raw); err == nil {
				err = coischema.ValidateProfileMap(raw)
			}
		}
		if err != nil {
			t.Errorf("skill toml block %d is not a valid profile: %v\n%s", i+1, err, src)
		}
	}
}
