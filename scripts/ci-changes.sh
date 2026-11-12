#!/usr/bin/env bash
# Decides whether a change touches code, for the CI `changes` job: a pull
# request that changes only non-code files (CHANGELOG.md, LICENSE, images,
# Markdown outside the code dirs) skips the heavy CI jobs, while `CI Success`
# still reports success, so the required check does not stay pending.
#
# Usage:
#   scripts/ci-changes.sh <base> <head>   classify `git diff <base> <head>`
#   scripts/ci-changes.sh < files         classify one path per line
#   scripts/ci-changes.sh --since-green   classify what changed on the PR
#                                         branch since its last green CI run
#
# --since-green skips a follow-up push that changes only non-code files after
# a green run (a CHANGELOG.md fix-up). It needs GH_TOKEN (with actions: read),
# REPO, WORKFLOW_FILE, HEAD_REF, HEAD_REPO, HEAD_SHA and RUN_ATTEMPT. A re-run,
# no earlier green run, a rebase or force-push, or an API error give code=true.
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

api() {
  curl -sf --retry 3 -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/$1"
}

# Files changed since the head of the last green run of this workflow on the
# same PR branch; fails (code=true) when there is no such safe base
since_green() {
  local runs prev cmp
  [ "$RUN_ATTEMPT" = "1" ] || { echo "Re-run (attempt $RUN_ATTEMPT)" >&2; return 1; }
  runs="$(api "actions/workflows/$WORKFLOW_FILE/runs?event=pull_request&status=success&per_page=30&branch=$(jq -rn --arg b "$HEAD_REF" '$b|@uri')")" || return 1
  prev="$(jq -r --arg repo "$HEAD_REPO" --arg sha "$HEAD_SHA" '
    [.workflow_runs[] | select(.head_repository.full_name == $repo and .head_sha != $sha
      and .conclusion == "success")] | sort_by(.created_at) | last | .head_sha // empty' <<< "$runs")" || return 1
  [ -n "$prev" ] || { echo "No earlier green run on this branch" >&2; return 1; }
  cmp="$(api "compare/$prev...$HEAD_SHA?per_page=100")" || return 1
  # ahead: the green head is an ancestor; a rebase or force-push gives diverged
  [ "$(jq -r .status <<< "$cmp")" = "ahead" ] || { echo "$prev is not an ancestor of $HEAD_SHA" >&2; return 1; }
  [ "$(jq -r '.files | length' <<< "$cmp")" -lt 100 ] || return 1
  echo "Since green run at $prev:" >&2
  jq -r '.files[] | .filename, (.previous_filename // empty)' <<< "$cmp"
}

if [ "${1:-}" = "--since-green" ]; then
  tree="${CI_CHANGES_TREE:-HEAD}"
  changed="$(since_green)" || result true
elif [ $# -eq 2 ]; then
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
