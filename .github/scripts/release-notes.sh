#!/usr/bin/env bash
set -euo pipefail

previous="${1:-}"
output="${2:-RELEASE_NOTES.md}"

if [[ -n "$previous" ]]; then
	range="$previous..HEAD"
else
	range="HEAD"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
: >"$tmpdir/breaking"
: >"$tmpdir/features"
: >"$tmpdir/fixes"
: >"$tmpdir/other"

while IFS=$'\t' read -r sha subject; do
	body="$(git show -s --format='%B' "$sha")"
	entry="$(printf -- '- %s (`%s`)' "$subject" "${sha:0:7}")"
	if grep -Eq '^[A-Za-z][A-Za-z0-9_-]*(\([^)]*\))?!:' <<<"$subject" ||
		grep -Eq '^BREAKING([ -])CHANGE:' <<<"$body"; then
		printf '%s\n' "$entry" >>"$tmpdir/breaking"
	elif grep -Eq '^feat(\([^)]*\))?:' <<<"$subject"; then
		printf '%s\n' "$entry" >>"$tmpdir/features"
	elif grep -Eq '^fix(\([^)]*\))?:' <<<"$subject"; then
		printf '%s\n' "$entry" >>"$tmpdir/fixes"
	else
		printf '%s\n' "$entry" >>"$tmpdir/other"
	fi
done < <(git log --reverse --format='%H%x09%s' "$range")

append_section() {
	local title="$1"
	local file="$2"
	if [[ -s "$file" ]]; then
		printf '## %s\n\n' "$title"
		cat "$file"
		printf '\n'
	fi
}

{
	append_section "Breaking Changes" "$tmpdir/breaking"
	append_section "Features" "$tmpdir/features"
	append_section "Fixes" "$tmpdir/fixes"
	append_section "Other Changes" "$tmpdir/other"
} >"$output"
