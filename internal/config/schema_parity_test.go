package config

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	coischema "github.com/coipond/coi/schema"
)

// Every TOML key a profile can carry must exist in the profile JSON schema, and
// vice versa. Profiles are schema-validated with additionalProperties: false,
// so a field added to the Go config without a schema entry makes any profile
// that sets it fail to load — which then breaks every coi command (this
// happened for [git] protected_branches, #862, and [limits.disk] size). This
// walks every struct reachable from ProfileConfig alongside the schema.
func TestProfileSchemaMatchesConfigStructs(t *testing.T) {
	raw, err := coischema.GetProfileSchema()
	if err != nil {
		t.Fatalf("GetProfileSchema: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	defs, _ := root["$defs"].(map[string]any)

	resolve := func(node map[string]any) map[string]any {
		for node != nil {
			ref, ok := node["$ref"].(string)
			if !ok {
				return node
			}
			next, _ := defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
			node = next
		}
		return nil
	}

	var problems []string
	var walk func(typ reflect.Type, node map[string]any, path string)
	walk = func(typ reflect.Type, node map[string]any, path string) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		node = resolve(node)
		if node == nil || typ.Kind() != reflect.Struct {
			return
		}
		props, ok := node["properties"].(map[string]any)
		if !ok {
			return // free-form object in the schema
		}
		seen := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("toml"), ",")[0]
			if !f.IsExported() || name == "" || name == "-" {
				continue
			}
			seen[name] = true
			child, ok := props[name].(map[string]any)
			if !ok {
				problems = append(problems, "missing from schema: "+path+name)
				continue
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			switch ft.Kind() {
			case reflect.Struct:
				walk(ft, child, path+name+".")
			case reflect.Slice:
				if items, ok := resolve(child)["items"].(map[string]any); ok {
					walk(ft.Elem(), items, path+name+"[].")
				}
			case reflect.Map:
				if ap, ok := resolve(child)["additionalProperties"].(map[string]any); ok {
					walk(ft.Elem(), ap, path+name+".<key>.")
				}
			}
		}
		for name := range props {
			if !seen[name] {
				problems = append(problems, "in schema but not in Go config: "+path+name)
			}
		}
	}
	walk(reflect.TypeOf(ProfileConfig{}), root, "")

	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}
