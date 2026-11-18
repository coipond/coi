package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/alias"
)

func TestResolveNameOrAlias_PrefixedAliasErrorsReachCaller(t *testing.T) {
	t.Setenv("COI_CONTAINER_PREFIX", "")
	t.Setenv("HOME", t.TempDir())
	reg, err := alias.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("coi-web", "/ws/web", ""); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	list := `[{"name":"coi-bbbbbbbb-1","status":"Running","config":{"user.coi.alias":"coi-web"}},` +
		`{"name":"coi-bbbbbbbb-2","status":"Running","config":{"user.coi.alias":"coi-web"}}]`
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte("#!/bin/sh\necho '"+list+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, err := resolveNameOrAlias("coi-web"); err == nil || !strings.Contains(err.Error(), "matches 2 running containers") {
		t.Errorf("resolveNameOrAlias(\"coi-web\") error = %v, want the disambiguation error", err)
	}
	if _, err := resolveNameOrAlias("coi-web-3"); err == nil || !strings.Contains(err.Error(), "not found at slot 3") {
		t.Errorf("resolveNameOrAlias(\"coi-web-3\") error = %v, want the slot error", err)
	}
	got, err := resolveNameOrAlias("coi-web-2")
	if err != nil || got != "coi-bbbbbbbb-2" {
		t.Errorf("resolveNameOrAlias(\"coi-web-2\") = %q, %v; want coi-bbbbbbbb-2", got, err)
	}
}
