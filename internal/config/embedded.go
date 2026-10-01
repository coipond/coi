package config

import (
	_ "embed"
)

// EmbeddedDefaultConfig is the built-in default configuration TOML that
// GetDefaultConfig parses as the base layer of every config.
//
//go:embed embedded/default_config.toml
var EmbeddedDefaultConfig []byte

// EmbeddedStarterConfig is the curated, commented main-config template written by
// `coi profile create default`. Unlike EmbeddedDefaultConfig (the terse,
// fully-active source the loader parses), this overrides nothing by default:
// every value is commented out so a generated config keeps inheriting built-in
// defaults until the user uncomments a line.
//
// It lives in the package dir (not the build-generated embedded/ dir) because it
// is static — no build-time transform — so it needs no copy step and is tracked
// directly.
//
//go:embed config.starter.toml
var EmbeddedStarterConfig []byte
