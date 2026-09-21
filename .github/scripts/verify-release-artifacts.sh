#!/usr/bin/env bash
set -euo pipefail

dist="${1:-${DIST_DIR:-dist}}"
linux_dir="$dist/linux-amd64"
commands=(lnproxy-client lnproxy-init lnproxy-node lnproxy-probe)

if ! command -v file >/dev/null 2>&1; then
	echo "file is required to verify release artifacts" >&2
	exit 1
fi
if ! command -v readelf >/dev/null 2>&1; then
	echo "readelf is required to verify release artifacts" >&2
	exit 1
fi

for cmd in "${commands[@]}"; do
	binary="$linux_dir/$cmd"
	if [[ ! -x "$binary" ]]; then
		echo "missing executable Linux artifact: $binary" >&2
		exit 1
	fi

	file_output="$(file "$binary")"
	if [[ "$file_output" != *"ELF 64-bit"* ||
		"$file_output" != *"x86-64"* ||
		"$file_output" != *"statically linked"* ]]; then
		echo "Linux artifact is not a static amd64 ELF: $binary" >&2
		echo "$file_output" >&2
		exit 1
	fi

	dynamic_output="$(readelf -d "$binary" 2>&1)"
	if [[ "$dynamic_output" == *"NEEDED"* ||
		"$dynamic_output" == *"RPATH"* ||
		"$dynamic_output" == *"RUNPATH"* ]]; then
		echo "Linux artifact has dynamic linker dependencies: $binary" >&2
		echo "$dynamic_output" >&2
		exit 1
	fi
done

archive="$(find "$dist" -maxdepth 1 -type f -name 'lnproxy-v*-amd64.zip' -print -quit)"
if [[ -z "$archive" ]]; then
	echo "release archive was not found in $dist" >&2
	exit 1
fi

expected=(
	linux-amd64/lnproxy-client
	linux-amd64/lnproxy-init
	linux-amd64/lnproxy-node
	linux-amd64/lnproxy-probe
	windows-amd64/lnproxy-client.exe
	windows-amd64/lnproxy-init.exe
	windows-amd64/lnproxy-node.exe
	windows-amd64/lnproxy-probe.exe
	windows-amd64/lnproxy-windows-server.exe
	README.md
	README.zh-CN.md
)
archive_list="$(unzip -Z1 "$archive")"
for path in "${expected[@]}"; do
	if ! grep -Fxq "$path" <<<"$archive_list"; then
		echo "release archive is missing $path" >&2
		exit 1
	fi
done

printf 'verified static Linux artifacts and archive contents: %s\n' "$archive"
