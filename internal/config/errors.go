package config

import "fmt"

// ConfigError marks a failure to load, parse, or validate configuration, as
// opposed to a runtime or environment failure. The CLI uses errors.As to map it
// to a dedicated exit code and to frame the message as a configuration problem
// the user must fix in their config, rather than a transient error to retry.
//
// Path, when set, is the config file or key path the failure relates to; it may
// be empty when the wrapped error already names its source.
type ConfigError struct {
	Path string
	Err  error
}

// Error describes the invalid configuration, naming the file when Path is set.
func (e *ConfigError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("invalid configuration (%s): %v", e.Path, e.Err)
	}
	return fmt.Sprintf("invalid configuration: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ConfigError) Unwrap() error { return e.Err }
