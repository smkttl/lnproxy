#!/usr/bin/env bash
set -euo pipefail

output="${GITHUB_OUTPUT:-/dev/stdout}"

mapfile -t tags < <(
	git tag --list 'v*' --sort=-v:refname |
		grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true
)
latest="${tags[0]:-}"
previous="${tags[1]:-}"

# If the latest tag points at HEAD, a normal push is a retry. Find the
# previous release so the tag is not recreated and notes remain meaningful.
if [[ -n "$latest" ]] && [[ "$(git rev-list -n 1 "$latest")" == "$(git rev-parse HEAD)" ]]; then
	printf 'has_release=true\n' >>"$output"
	printf 'version=%s\n' "$latest" >>"$output"
	printf 'previous=%s\n' "$previous" >>"$output"
	exit 0
fi

write_no_release() {
	printf 'has_release=false\n' >>"$output"
	printf 'version=\n' >>"$output"
	printf 'previous=\n' >>"$output"
}

if [[ -n "$latest" ]]; then
	range="$latest..HEAD"
else
	range="HEAD"
fi

subjects="$(git log --format='%s' "$range")"
messages="$(git log --format='%B' "$range")"

bump=""
if grep -Eq '^[A-Za-z][A-Za-z0-9_-]*(\([^)]*\))?!:' <<<"$subjects" ||
	grep -Eq '^BREAKING([ -])CHANGE:' <<<"$messages"; then
	bump="major"
elif grep -Eq '^feat(\([^)]*\))?:' <<<"$subjects"; then
	bump="minor"
elif grep -Eq '^fix(\([^)]*\))?:' <<<"$subjects"; then
	bump="patch"
fi

if [[ -z "$bump" ]]; then
	write_no_release
	exit 0
fi

if [[ -z "$latest" ]]; then
	version="v1.0.0"
else
	base="${latest#v}"
	IFS=. read -r major minor patch <<<"$base"
	case "$bump" in
	major)
		major=$((major + 1))
		minor=0
		patch=0
		;;
	minor)
		minor=$((minor + 1))
		patch=0
		;;
	patch)
		patch=$((patch + 1))
		;;
	esac
	version="v${major}.${minor}.${patch}"
fi

printf 'has_release=true\n' >>"$output"
printf 'version=%s\n' "$version" >>"$output"
printf 'previous=%s\n' "$latest" >>"$output"
