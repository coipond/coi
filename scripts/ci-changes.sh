#!/usr/bin/env bash
# Decides whether a change touches code, for the CI `changes` job: a pull
# request that changes only non-code files (CHANGELOG.md, LICENSE, images,
# Markdown outside the code dirs) skips the heavy CI jobs, while `CI Success`
# still reports success, so the required check does not stay pending.
#
# Usage:
#   scripts/ci-changes.sh <base> <head>   classify `git diff <base> <head>`
#   scripts/ci-changes.sh < files         classify one path per line
#
# Prints the changed files and `code=true|false`, and appends `code=...` to
# $GITHUB_OUTPUT when set. Markdown directories are judged against the tree of
# $CI_CHANGES_TREE (default: the head, or HEAD with stdin). Anything unexpected
# (a git error, an empty change, an unknown file) gives code=true: when in
# doubt, run everything.

set -uo pipefail

result() {
  echo "code=$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "code=$1" >> "$GITHUB_OUTPUT"
  fi
  exit 0
}

if [ $# -eq 2 ]; then
  tree="${CI_CHANGES_TREE:-$2}"
  changed="$(git diff --name-only --no-renames "$1" "$2")" || result true
else
  tree="${CI_CHANGES_TREE:-HEAD}"
  changed="$(cat)" || result true
fi

echo "Changed files:"
echo "$changed"

[ -n "$changed" ] || result true

# Markdown and images in a Go package dir may be embedded or read by tests.
# A git error counts as a Go dir (code).
in_go_dir() {
  local dir entries
  dir="$(dirname "$1")"
  [ "$dir" != "." ] || return 1
  entries="$(git ls-tree --name-only "$tree" -- "$dir/")" || return 0
  grep -q '\.go$' <<< "$entries"
}

code=false
while IFS= read -r file; do
  case "$file" in
    # Code dirs: anything here is code, Markdown included
    cmd/*|internal/*|pkg/*|tests/*|testdata/*|profiles/*|schema/*|skills/*|scripts/*) code=true ;;
    # Read by TestREADMETomlExamplesLoad (internal/config/readme_examples_test.go)
    README.md) code=true ;;
    CHANGELOG.md|LICENSE*|.github/ISSUE_TEMPLATE/*|.github/FUNDING.yml) ;;
    *.md|*.png|*.jpg|*.jpeg|*.gif|*.svg)
      if in_go_dir "$file"; then code=true; fi ;;
    *) code=true ;;
  esac
  [ "$code" = false ] || break
done <<< "$changed"

result "$code"
