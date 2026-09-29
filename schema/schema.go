// Package schema provides access to the Coi profile JSON Schema.
// External tools (e.g. a Rails web UI) can consume the schema via
// `coi schema profile` and validate profile config.toml data before
// writing it to disk — no need to duplicate field-level validation.
//
// Source layout: the root schema (profile.schema.json) holds only the
// top-level property declarations.  Each sub-type lives in its own file
// under defs/ (e.g. defs/NetworkConfig.json).  GetProfileSchema bundles
// all defs into a single self-contained document so consumers do not need
// a multi-file resolver.
package schema

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed profile.schema.json
var rootSchemaBytes []byte

//go:embed defs/*.json
var defsFS embed.FS

// GetProfileSchema returns a self-contained JSON Schema 2020-12 document
// describing the full Coi profile config.toml structure.  All sub-type
// definitions from defs/ are bundled inline so the output can be used
// by any validator without additional file resolution.
func GetProfileSchema() ([]byte, error) {
	return bundle()
}

// compiled holds the lazily-compiled JSON Schema validator (thread-safe).
var (
	compiledOnce   sync.Once
	compiledSchema *jsonschema.Schema
	errCompiled    error
)

// ValidateProfileMap validates a profile represented as a map (e.g. decoded
// from a TOML config.toml) against the JSON Schema.  Returns nil if the
// profile is structurally valid, or a descriptive error listing every
// violation found.
//
// The map values must use standard JSON-compatible Go types (string, bool,
// float64, []any, map[string]any).  Values decoded from TOML via
// github.com/BurntSushi/toml into map[string]any satisfy this after a
// JSON round-trip; call this helper after marshaling to JSON and back if
// your source uses int64 or other non-JSON types.
func ValidateProfileMap(data map[string]any) error {
	compiledOnce.Do(func() {
		bundled, err := bundle()
		if err != nil {
			errCompiled = fmt.Errorf("failed to bundle profile schema: %w", err)
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		var bundledDoc any
		if err := json.Unmarshal(bundled, &bundledDoc); err != nil {
			errCompiled = fmt.Errorf("failed to parse bundled schema: %w", err)
			return
		}
		if err := compiler.AddResource("profile.schema.json", bundledDoc); err != nil {
			errCompiled = fmt.Errorf("failed to register profile schema: %w", err)
			return
		}
		compiledSchema, errCompiled = compiler.Compile("profile.schema.json")
	})
	if errCompiled != nil {
		return errCompiled
	}

	// Convert to canonical JSON types (TOML int64 → float64 etc.)
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to serialize profile for validation: %w", err)
	}
	var jsonValue any
	if err := json.Unmarshal(jsonBytes, &jsonValue); err != nil {
		return fmt.Errorf("failed to deserialize profile for validation: %w", err)
	}

	if err := compiledSchema.Validate(jsonValue); err != nil {
		return err
	}
	return nil
}

// ValidationIssue is a single schema violation with the JSON-pointer path to
// the offending value and a human-readable message.
type ValidationIssue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ExtractErrors converts a schema validation error into a flat slice of
// ValidationIssue values.  Returns nil when err is nil.  Non-schema errors
// (e.g. TOML parse failures) are returned as a single issue with an empty path.
func ExtractErrors(err error) []ValidationIssue {
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []ValidationIssue{{Path: "", Message: err.Error()}}
	}
	return flattenOutputUnit(ve.BasicOutput())
}

func flattenOutputUnit(u *jsonschema.OutputUnit) []ValidationIssue {
	if len(u.Errors) == 0 {
		msg := ""
		if u.Error != nil {
			msg = u.Error.String()
		}
		return []ValidationIssue{{Path: u.InstanceLocation, Message: msg}}
	}
	var issues []ValidationIssue
	for i := range u.Errors {
		issues = append(issues, flattenOutputUnit(&u.Errors[i])...)
	}
	return issues
}

// bundle merges defs/*.json into the root schema's $defs and returns the
// resulting self-contained document.
func bundle() ([]byte, error) {
	var root map[string]any
	if err := json.Unmarshal(rootSchemaBytes, &root); err != nil {
		return nil, fmt.Errorf("failed to parse root schema: %w", err)
	}

	entries, err := defsFS.ReadDir("defs")
	if err != nil {
		return nil, fmt.Errorf("failed to read defs directory: %w", err)
	}

	defs := make(map[string]any, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := defsFS.ReadFile("defs/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read def file %s: %w", entry.Name(), err)
		}
		var def any
		if err := json.Unmarshal(data, &def); err != nil {
			return nil, fmt.Errorf("failed to parse def file %s: %w", entry.Name(), err)
		}
		key := strings.TrimSuffix(entry.Name(), ".json")
		defs[key] = def
	}

	root["$defs"] = defs
	return json.MarshalIndent(root, "", "  ")
}
