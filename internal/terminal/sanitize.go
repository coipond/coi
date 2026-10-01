// Package terminal adapts host terminal settings for use inside containers.
package terminal

import "strings"

// standardXterm is the set of xterm-* TERM values that a minimal container
// (ncurses-base, no ncurses-term) reliably ships terminfo for, so they pass
// through untouched. Any OTHER xterm-* value — emulator variants (xterm-kitty,
// xterm-ghostty, …) AND the less-common xterm-16color/xterm-88color, which live
// in ncurses-term and may be absent — is mapped to xterm-256color, a safe
// superset that is always present.
var standardXterm = map[string]bool{
	"xterm":          true,
	"xterm-color":    true,
	"xterm-256color": true,
}

// exoticPrefixes are non-xterm TERM names set by modern terminal emulators that
// commonly lack a terminfo entry in a minimal container. Matched by prefix so
// variants (e.g. "foot-extra", "tmux-256color") are covered.
var exoticPrefixes = []string{
	"wezterm",
	"alacritty",
	"kitty", // some setups export bare "kitty"; the real default is "xterm-kitty" (handled below)
	"foot",
	"rio",
	"contour",
	"st-",           // suckless st: "st-256color"
	"tmux-256color", // bare "tmux"/"screen" terminfo is usually present; the 256color variants often aren't
	"screen-256color",
}

// SanitizeTerm returns a TERM value compatible with most container environments.
// Modern terminals like kitty (TERM=xterm-kitty), Ghostty (xterm-ghostty),
// WezTerm, foot, etc. often have no terminfo entry inside the container, so tmux
// aborts with "missing or unsuitable terminal: <TERM>". We map such values to a
// widely-available 256-color equivalent that preserves color support, while
// letting genuinely standard TERMs pass through unchanged.
//
// The rule is deliberately broad on the xterm- namespace: any xterm-<vendor>
// value that is not one of the standard entries is mapped, so a new emulator
// (the next xterm-kitty) is handled without another code change (#772).
func SanitizeTerm(term string) string {
	if term == "" {
		return "xterm-256color"
	}

	// Standard xterm variants ship in the container — keep them (and their
	// color depth) as-is.
	if standardXterm[term] {
		return term
	}

	// Every other xterm-* value is an emulator-specific variant (xterm-kitty,
	// xterm-ghostty, …) that the container likely can't resolve.
	if strings.HasPrefix(term, "xterm-") {
		return "xterm-256color"
	}

	// Non-xterm exotic terminals.
	for _, p := range exoticPrefixes {
		if strings.HasPrefix(term, p) {
			return "xterm-256color"
		}
	}

	// Standard non-xterm terms (vt100, linux, screen, ansi, custom, …) pass
	// through — they are either present in the container or the caller's own.
	return term
}
