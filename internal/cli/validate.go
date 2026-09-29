package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	coischema "github.com/mensfeld/code-on-incus/schema"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate Coi configuration files",
	Long: `Validate Coi configuration files and report any errors.

Use --format json for machine-readable output (e.g. from a web UI or script).
Exit code 0 = valid, 1 = invalid.`,
	// Cobra stops at the first PersistentPreRunE it finds walking up from the
	// leaf, so this prevents rootCmd.PersistentPreRunE (config loading) from
	// running for the validate subtree.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var validateProfileCmd = &cobra.Command{
	Use:   "profile <path>",
	Short: "Validate a profile config.toml against the Coi JSON Schema",
	Long: `Validate a profile config.toml against the Coi JSON Schema.

Text output (default):
  Profile is valid.
  Profile validation failed:
    /network/mode: value must be one of "open", "restricted", "allowlist"

JSON output (--format json):
  {"valid": true,  "errors": []}
  {"valid": false, "errors": [{"path": "/network/mode", "message": "..."}]}

Exit code 0 = valid, 1 = invalid.

Examples:
  coi validate profile ~/.coi/profiles/myproject/config.toml
  coi validate profile config.toml --format json | jq '.errors[]'

  # Ruby / Rails — shell out without needing a JSON Schema library:
  result = JSON.parse(` + "`coi validate profile #{Shellwords.escape(path)} --format json`" + `)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		format, _ := cmd.Flags().GetString("format")
		applyJSONFormatAlias(cmd, &format)
		if format != "text" && format != "json" {
			return &ExitCodeError{Code: 2, Message: fmt.Sprintf("invalid format %q: must be 'text' or 'json'", format)}
		}

		path := args[0]

		var rawMap map[string]any
		if _, err := toml.DecodeFile(path, &rawMap); err != nil {
			emitValidateOutput(format, false,
				[]coischema.ValidationIssue{{Path: "", Message: fmt.Sprintf("failed to parse TOML: %s", err)}})
			return &ExitCodeError{Code: 1}
		}

		schemaErr := coischema.ValidateProfileMap(rawMap)
		if schemaErr == nil {
			emitValidateOutput(format, true, nil)
			return nil
		}

		emitValidateOutput(format, false, coischema.ExtractErrors(schemaErr))
		return &ExitCodeError{Code: 1}
	},
}

func emitValidateOutput(format string, valid bool, issues []coischema.ValidationIssue) {
	if format == "json" {
		errs := issues
		if errs == nil {
			errs = []coischema.ValidationIssue{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Valid  bool                        `json:"valid"`
			Errors []coischema.ValidationIssue `json:"errors"`
		}{Valid: valid, Errors: errs})
		return
	}

	// Text format
	if valid {
		fmt.Println("Profile is valid.")
		return
	}
	fmt.Fprintln(os.Stderr, "Profile validation failed:")
	for _, issue := range issues {
		path := issue.Path
		if path == "" {
			path = "(root)"
		}
		fmt.Fprintf(os.Stderr, "  %s: %s\n", path, strings.TrimRight(issue.Message, "."))
	}
}

func init() {
	validateProfileCmd.Flags().String("format", "text", "Output format: text or json")
	validateProfileCmd.Flags().Bool("json", false, "Alias for --format json")
	validateCmd.AddCommand(validateProfileCmd)
}
