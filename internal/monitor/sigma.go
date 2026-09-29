package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// sigmaFieldCheck represents a single field condition in a Sigma detection entry.
type sigmaFieldCheck struct {
	Field    string   // "Image", "CommandLine", "ParentImage", "ParentCommandLine"
	Modifier string   // "contains", "endswith", "startswith", "contains_all"
	Values   []string // OR list for contains/endswith/startswith; ALL required for contains_all
}

// sigmaAlternative is a group of field checks that must ALL match (AND within group).
type sigmaAlternative []sigmaFieldCheck

// sigmaSelection is a list of alternatives where ANY one must match (OR between groups).
// A simple (non-list) detection map produces a selection with one alternative.
type sigmaSelection []sigmaAlternative

// sigmaPattern is a compiled Sigma rule ready for efficient matching.
type sigmaPattern struct {
	Title       string
	Level       string           // "high" or "critical"
	Required    []sigmaSelection // evaluated according to ConditionOp
	ConditionOp string           // "and": all Required must match; "or": any Required must match
	Forbidden   []sigmaSelection // if any Forbidden selection matches, the rule is excluded
}

// sigmaRuleYAML holds the raw parsed YAML fields we care about.
type sigmaRuleYAML struct {
	Title     string                 `yaml:"title"`
	Level     string                 `yaml:"level"`
	Logsource map[string]string      `yaml:"logsource"`
	Detection map[string]interface{} `yaml:"detection"`
}

// loadSigmaPatterns loads Sigma linux/process_creation rules from
// <cloneDir>/rules/linux/process_creation/. Returns nil without error when the
// directory is absent — Sigma patterns are optional and purely additive.
func loadSigmaPatterns(cloneDir string) []sigmaPattern {
	rulesDir := filepath.Join(cloneDir, "rules", "linux", "process_creation")
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil
	}

	var patterns []sigmaPattern
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
		if err != nil {
			continue
		}
		p, ok := compileSigmaFile(data)
		if ok {
			patterns = append(patterns, p)
		}
	}
	return patterns
}

// compileSigmaFile parses raw YAML and compiles it to a sigmaPattern.
// Returns (_, false) when the rule should be skipped: wrong log source,
// unsupported condition syntax, or severity below high.
func compileSigmaFile(data []byte) (sigmaPattern, bool) {
	var raw sigmaRuleYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return sigmaPattern{}, false
	}

	// Only linux/process_creation rules map to what Coi collects.
	if raw.Logsource["product"] != "linux" || raw.Logsource["category"] != "process_creation" {
		return sigmaPattern{}, false
	}

	// Only load actionable severity levels.
	level := strings.ToLower(raw.Level)
	if level != "high" && level != "critical" {
		return sigmaPattern{}, false
	}

	if len(raw.Detection) == 0 {
		return sigmaPattern{}, false
	}

	condRaw, ok := raw.Detection["condition"]
	if !ok {
		return sigmaPattern{}, false
	}
	condition, ok := condRaw.(string)
	if !ok {
		return sigmaPattern{}, false
	}

	// Skip rules that use features outside our supported subset.
	for _, unsupported := range []string{"|", " count", " near", " min(", " max(", " avg("} {
		if strings.Contains(condition, unsupported) {
			return sigmaPattern{}, false
		}
	}

	// Compile every named selection (all keys except "condition").
	compiledSels := make(map[string]sigmaSelection, len(raw.Detection))
	for key, val := range raw.Detection {
		if key == "condition" {
			continue
		}
		sel, ok := compileSigmaSelection(val)
		if !ok {
			return sigmaPattern{}, false // unsupported modifier — skip the whole rule
		}
		compiledSels[key] = sel
	}

	p := sigmaPattern{
		Title: raw.Title,
		Level: level,
	}
	if err := parseSigmaCondition(condition, compiledSels, &p); err != nil {
		return sigmaPattern{}, false
	}
	if len(p.Required) == 0 {
		return sigmaPattern{}, false
	}
	return p, true
}

// parseSigmaCondition interprets the condition string and populates p.Required,
// p.ConditionOp, and p.Forbidden.
func parseSigmaCondition(condition string, selections map[string]sigmaSelection, p *sigmaPattern) error {
	condition = strings.TrimSpace(condition)

	// Handle "X and not Y".
	if idx := strings.Index(condition, " and not "); idx >= 0 {
		reqPart := strings.TrimSpace(condition[:idx])
		notPart := strings.TrimSpace(condition[idx+len(" and not "):])

		required, op, err := parseSigmaSelectionExpr(reqPart, selections)
		if err != nil {
			return err
		}
		p.Required = required
		p.ConditionOp = op

		forbidden, _, err := parseSigmaSelectionExpr(notPart, selections)
		if err != nil {
			return err
		}
		p.Forbidden = forbidden
		return nil
	}

	// Handle "X and Y" (two or more named selections, no negation).
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		p.ConditionOp = "and"
		for _, part := range parts {
			sels, op, err := parseSigmaSelectionExpr(strings.TrimSpace(part), selections)
			if err != nil {
				return err
			}
			if op == "or" {
				// "1 of X_*" sub-expression: merge all matched selections into one
				// OR-group so the overall AND semantics is preserved correctly.
				merged := make(sigmaSelection, 0)
				for _, sel := range sels {
					merged = append(merged, sel...)
				}
				p.Required = append(p.Required, merged)
			} else {
				p.Required = append(p.Required, sels...)
			}
		}
		return nil
	}

	// Handle "X or Y" between named selections.
	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		p.ConditionOp = "or"
		for _, part := range parts {
			sels, _, err := parseSigmaSelectionExpr(strings.TrimSpace(part), selections)
			if err != nil {
				return err
			}
			p.Required = append(p.Required, sels...)
		}
		return nil
	}

	// Simple expression: "selection", "all of selection_*", "1 of selection_*", etc.
	required, op, err := parseSigmaSelectionExpr(condition, selections)
	if err != nil {
		return err
	}
	p.Required = required
	p.ConditionOp = op
	return nil
}

// parseSigmaSelectionExpr resolves a single selection expression to matched
// selections and the AND/OR operator.
func parseSigmaSelectionExpr(expr string, selections map[string]sigmaSelection) ([]sigmaSelection, string, error) {
	expr = strings.TrimSpace(expr)

	if strings.HasPrefix(expr, "1 of ") {
		pattern := strings.TrimPrefix(expr, "1 of ")
		sels := matchSigmaGlob(pattern, selections)
		if len(sels) == 0 {
			return nil, "", fmt.Errorf("sigma: no selections matched %q", expr)
		}
		return sels, "or", nil
	}

	if strings.HasPrefix(expr, "all of ") {
		pattern := strings.TrimPrefix(expr, "all of ")
		sels := matchSigmaGlob(pattern, selections)
		if len(sels) == 0 {
			return nil, "", fmt.Errorf("sigma: no selections matched %q", expr)
		}
		return sels, "and", nil
	}

	sel, ok := selections[expr]
	if !ok {
		return nil, "", fmt.Errorf("sigma: unknown selection %q", expr)
	}
	return []sigmaSelection{sel}, "and", nil
}

// matchSigmaGlob returns selections whose names match the given pattern
// ("them", "selection_*", "filter*", etc.).
func matchSigmaGlob(pattern string, selections map[string]sigmaSelection) []sigmaSelection {
	if pattern == "them" {
		sels := make([]sigmaSelection, 0, len(selections))
		for _, sel := range selections {
			sels = append(sels, sel)
		}
		return sels
	}
	var sels []sigmaSelection
	for name, sel := range selections {
		if matched, err := filepath.Match(pattern, name); err == nil && matched {
			sels = append(sels, sel)
		}
	}
	return sels
}

// compileSigmaSelection parses a detection selection value (map or list of maps)
// into a sigmaSelection. Returns (nil, false) on unsupported input.
func compileSigmaSelection(raw interface{}) (sigmaSelection, bool) {
	switch v := raw.(type) {
	case map[string]interface{}:
		alt, ok := compileSigmaAlternative(v)
		if !ok {
			return nil, false
		}
		return sigmaSelection{alt}, true
	case []interface{}:
		sel := make(sigmaSelection, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				return nil, false
			}
			alt, ok := compileSigmaAlternative(m)
			if !ok {
				return nil, false
			}
			sel = append(sel, alt)
		}
		return sel, true
	default:
		return nil, false
	}
}

// compileSigmaAlternative compiles a map of "Field|modifier: values" entries.
func compileSigmaAlternative(m map[string]interface{}) (sigmaAlternative, bool) {
	alt := make(sigmaAlternative, 0, len(m))
	for fieldKey, val := range m {
		check, ok := compileSigmaFieldCheck(fieldKey, val)
		if !ok {
			return nil, false
		}
		alt = append(alt, check)
	}
	return alt, true
}

// compileSigmaFieldCheck parses a single "Field|modifier: value(s)" entry.
// Returns (_, false) for unsupported fields or modifiers (e.g. |re).
func compileSigmaFieldCheck(fieldKey string, raw interface{}) (sigmaFieldCheck, bool) {
	parts := strings.Split(fieldKey, "|")
	fieldName := parts[0]
	modifiers := parts[1:]

	var field string
	switch strings.ToLower(fieldName) {
	case "image":
		field = "Image"
	case "commandline":
		field = "CommandLine"
	case "parentimage":
		field = "ParentImage"
	case "parentcommandline":
		field = "ParentCommandLine"
	default:
		return sigmaFieldCheck{}, false
	}

	modifier := "glob"
	switch len(modifiers) {
	case 0:
		// no modifier — Sigma spec: exact match (case-insensitive), wildcards (* ?) allowed
	case 1:
		switch strings.ToLower(modifiers[0]) {
		case "contains":
			modifier = "contains"
		case "endswith":
			modifier = "endswith"
		case "startswith":
			modifier = "startswith"
		default:
			return sigmaFieldCheck{}, false
		}
	case 2:
		if strings.ToLower(modifiers[0]) == "contains" && strings.ToLower(modifiers[1]) == "all" {
			modifier = "contains_all"
		} else {
			return sigmaFieldCheck{}, false
		}
	default:
		return sigmaFieldCheck{}, false
	}

	values, ok := sigmaToStringList(raw)
	if !ok || len(values) == 0 {
		return sigmaFieldCheck{}, false
	}
	return sigmaFieldCheck{Field: field, Modifier: modifier, Values: values}, true
}

// sigmaToStringList converts a string or []interface{} YAML value to []string.
func sigmaToStringList(raw interface{}) ([]string, bool) {
	switch v := raw.(type) {
	case string:
		return []string{v}, true
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

// matchSigmaPattern returns true if the given process fields match the compiled rule.
func matchSigmaPattern(image, cmdline, parentImage, parentCmdline string, p sigmaPattern) bool {
	fields := map[string]string{
		"Image":             strings.ToLower(image),
		"CommandLine":       strings.ToLower(cmdline),
		"ParentImage":       strings.ToLower(parentImage),
		"ParentCommandLine": strings.ToLower(parentCmdline),
	}

	// A matching forbidden selection disqualifies this rule.
	for _, sel := range p.Forbidden {
		if evalSigmaSelection(fields, sel) {
			return false
		}
	}

	if len(p.Required) == 0 {
		return false
	}

	if p.ConditionOp == "or" {
		for _, sel := range p.Required {
			if evalSigmaSelection(fields, sel) {
				return true
			}
		}
		return false
	}

	// Default "and": every required selection must match.
	for _, sel := range p.Required {
		if !evalSigmaSelection(fields, sel) {
			return false
		}
	}
	return true
}

// evalSigmaSelection returns true if any alternative in the selection matches.
func evalSigmaSelection(fields map[string]string, sel sigmaSelection) bool {
	for _, alt := range sel {
		if evalSigmaAlternative(fields, alt) {
			return true
		}
	}
	return false
}

// evalSigmaAlternative returns true when all field checks in the alternative match.
func evalSigmaAlternative(fields map[string]string, alt sigmaAlternative) bool {
	for _, check := range alt {
		if !evalSigmaFieldCheck(fields[check.Field], check) {
			return false
		}
	}
	return true
}

// evalSigmaFieldCheck evaluates a field check against an already-lowercased value.
func evalSigmaFieldCheck(lowerVal string, check sigmaFieldCheck) bool {
	switch check.Modifier {
	case "glob":
		// No-modifier Sigma field: exact equality when no wildcards, glob when * or ? present.
		for _, v := range check.Values {
			if sigmaGlobMatch(strings.ToLower(v), lowerVal) {
				return true
			}
		}
		return false
	case "contains":
		for _, v := range check.Values {
			if strings.Contains(lowerVal, strings.ToLower(v)) {
				return true
			}
		}
		return false
	case "endswith":
		for _, v := range check.Values {
			if strings.HasSuffix(lowerVal, strings.ToLower(v)) {
				return true
			}
		}
		return false
	case "startswith":
		for _, v := range check.Values {
			if strings.HasPrefix(lowerVal, strings.ToLower(v)) {
				return true
			}
		}
		return false
	case "contains_all":
		for _, v := range check.Values {
			if !strings.Contains(lowerVal, strings.ToLower(v)) {
				return false
			}
		}
		return true
	}
	return false
}

// sigmaGlobMatch performs glob matching where * matches any sequence of
// characters and ? matches exactly one character. Both args must be lowercased.
func sigmaGlobMatch(pattern, text string) bool {
	p, t := 0, 0
	lastStar, matchStart := -1, 0

	for t < len(text) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == text[t]) {
			p++
			t++
		} else if p < len(pattern) && pattern[p] == '*' {
			lastStar = p
			matchStart = t
			p++
		} else if lastStar >= 0 {
			p = lastStar + 1
			matchStart++
			t = matchStart
		} else {
			return false
		}
	}

	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
