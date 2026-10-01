package cli

import (
	"fmt"

	coischema "github.com/coipond/coi/schema"
	"github.com/spf13/cobra"
)

// schemaCmd is the parent command for schema operations
var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Print machine-readable schemas for Coi configuration formats",
	Long: `Print JSON Schema documents that describe Coi configuration formats.

These schemas can be consumed by external tools (e.g. a web UI or editor
plugin) to validate configuration files without duplicating Coi's own
validation logic.`,
	// Cobra walks up from the leaf command and stops at the first
	// PersistentPreRunE it finds, so defining one here prevents
	// rootCmd.PersistentPreRunE from running for this subtree.
	// Schema output requires no local Coi setup.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

// schemaProfileCmd prints the JSON Schema for profile config.toml files
var schemaProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Print the JSON Schema for profile config.toml files",
	Long: `Print the JSON Schema (2020-12) that describes a Coi profile config.toml.

The schema covers every field accepted by a profile configuration file and
can be used with any JSON Schema validator. Because TOML and JSON share the
same data model for the types Coi uses, you can validate a parsed TOML
document directly against this schema.

Examples:
  # Inspect the schema
  coi schema profile | jq .

  # Save for use in a Rails app or editor plugin
  coi schema profile > profile.schema.json

  # Validate a profile with the Python jsonschema CLI
  python3 -c "
  import json, tomllib, jsonschema, sys
  schema = json.load(open('profile.schema.json'))
  data   = tomllib.load(open(sys.argv[1], 'rb'))
  jsonschema.validate(data, schema)
  print('valid')
  " path/to/config.toml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := coischema.GetProfileSchema()
		if err != nil {
			return fmt.Errorf("failed to build profile schema: %w", err)
		}
		_, err = fmt.Println(string(b))
		return err
	},
}

func init() {
	schemaCmd.AddCommand(schemaProfileCmd)
}
