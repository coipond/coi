#!/bin/bash
# Documentation coverage report (similar to yard-lint for Ruby): the share of
# exported top-level declarations — funcs, methods, types, consts, vars — that
# carry a godoc comment. golangci-lint's revive "exported" rule is the gate on
# individual symbols; this prints the overall picture and fails below THRESHOLD.
#
# Usage: scripts/doc-coverage.sh [dir]   (default: current directory)
#
# A comment documents a declaration only when it sits directly above it (a
# blank line detaches it, as in godoc); //go: and //nolint directives don't
# count as documentation. Specs in grouped `type ( ... )` blocks are counted;
# members of grouped `const ( ... )` / `var ( ... )` blocks are not. Test
# files, vendored code, generated files ("// Code generated ... DO NOT
# EDIT.") and the contents of raw string literals are skipped.

set -euo pipefail

THRESHOLD=80

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cd "${1:-.}"

echo "Checking documentation coverage..."
echo ""

# Inside a git checkout, list tracked files only, so scratch dirs (tmp/, build
# output) don't skew the numbers; otherwise fall back to find.
list_go_files() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files -- '*.go' ':!:*_test.go' ':!:vendor/**' ':!:*_generated.go'
  else
    find . -type f -name '*.go' -not -name '*_test.go' -not -name '*_generated.go' \
      -not -path '*/vendor/*' | sed 's|^\./||'
  fi
}

results=$(mktemp)
trap 'rm -f "$results"' EXIT

# One awk pass over every file. Portable (POSIX awk — no gawk-only match()
# arrays), so it runs with Ubuntu's default mawk too. Emits one
# "STATUS<TAB>file<TAB>kind<TAB>name" line per exported declaration.
# shellcheck disable=SC2016 # awk program, not shell — no expansion wanted
list_go_files | while IFS= read -r f; do printf '%s\0' "$f"; done |
  xargs -0 -r awk '
    FNR == 1 { doc = 0; inblock = 0; generated = 0; inraw = 0; intype = 0; typedoc = 0 }
    { sub(/\r$/, "") } # CRLF files
    /^\/\/ Code generated .* DO NOT EDIT\.$/ { generated = 1 }
    inblock {
      if ($0 ~ /\*\//) { inblock = 0; doc = 1 }
      next
    }
    # Raw string literals: a code line with an odd number of backticks (the
    # rune literal for a backtick aside) opens or closes one; lines that start
    # inside one are string content, not declarations. Comment lines do not
    # count — doc text often wraps a `quoted` phrase across lines.
    {
      wasraw = inraw
      if (inraw || $0 !~ /^[ \t]*\/\//) {
        bt = $0
        gsub(/\047`\047/, "", bt)
        if (gsub(/`/, "", bt) % 2 == 1) { inraw = !inraw }
      }
      if (wasraw) { doc = 0; next }
    }
    # Grouped type ( ... ) block: each one-tab-indented spec is a declaration,
    # documented by a comment right above it or by the block comment.
    /^type[ \t]*\($/ { intype = 1; typedoc = doc; doc = 0; next }
    intype {
      if ($0 ~ /^\)/) { intype = 0; doc = 0; next }
      if ($0 ~ /^\t\/\//) { doc = 1; next }
      if ($0 ~ /^\t[A-Za-z_]/) {
        name = substr($0, 2)
        sub(/[^A-Za-z0-9_].*$/, "", name)
        if (!generated && name ~ /^[A-Z]/) {
          printf "%s\t%s\t%s\t%s\n", ((doc || typedoc) ? "DOCUMENTED" : "MISSING"), FILENAME, "type", name
        }
      }
      doc = 0
      next
    }
    # Compiler/linter directives (//go:embed, //nolint:...) are not
    # documentation, but they may sit between a doc comment and its
    # declaration without detaching it.
    /^\/\/(go:|nolint|line |export |extern )/ { next }
    /^\/\// { doc = 1; next }
    /^\/\*/ {
      if ($0 ~ /\*\//) { doc = 1 } else { inblock = 1 }
      next
    }
    /^(func|type|const|var)[ \t]/ {
      kind = $1
      rest = substr($0, length(kind) + 2)
      sub(/^[ \t]+/, "", rest)
      if (kind == "func" && rest ~ /^\(/) {
        kind = "method"
        sub(/^\([^)]*\)[ \t]*/, "", rest) # drop the receiver
      }
      name = rest
      sub(/[^A-Za-z0-9_].*$/, "", name)
      if (!generated && name ~ /^[A-Z]/) {
        printf "%s\t%s\t%s\t%s\n", (doc ? "DOCUMENTED" : "MISSING"), FILENAME, kind, name
      }
    }
    { doc = 0 }
  ' >"$results"

TOTAL_EXPORTED=$(wc -l <"$results" | tr -d ' ')
MISSING_COUNT=$(grep -c '^MISSING' "$results" || true)
DOCUMENTED=$((TOTAL_EXPORTED - MISSING_COUNT))

if [ "$TOTAL_EXPORTED" -gt 0 ]; then
  COVERAGE=$(awk -v d="$DOCUMENTED" -v t="$TOTAL_EXPORTED" 'BEGIN { printf "%.1f", d / t * 100 }')
else
  COVERAGE=100.0
fi

echo "======================================"
echo "  Documentation Coverage Report"
echo "======================================"
echo ""
echo "Total exported symbols:  $TOTAL_EXPORTED"
echo "Documented:              $DOCUMENTED"
echo "Missing documentation:   $MISSING_COUNT"
echo ""

if [ "$MISSING_COUNT" -eq 0 ]; then
  echo -e "${GREEN}✓ Documentation coverage: ${COVERAGE}%${NC}"
  echo ""
  echo "All exported symbols are documented! 🎉"
  exit 0
fi

echo -e "${YELLOW}⚠ Documentation coverage: ${COVERAGE}%${NC}"
echo ""
echo "Missing documentation for:"
echo ""
grep '^MISSING' "$results" | while IFS=$'\t' read -r _ file kind name; do
  echo -e "  ${RED}✗${NC} $file"
  echo "    ${kind}: $name"
done
echo ""
echo -e "${YELLOW}Add godoc comments for all exported symbols${NC}"
echo "Format: // Name does something..."

if awk -v c="$COVERAGE" -v t="$THRESHOLD" 'BEGIN { exit !(c < t) }'; then
  echo ""
  echo -e "${RED}✗ Documentation coverage ${COVERAGE}% is below threshold ${THRESHOLD}%${NC}"
  exit 1
fi
