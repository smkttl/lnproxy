#!/usr/bin/env bash
set -euo pipefail

dist="${1:-${DIST_DIR:-dist}}"
image="${LINUX_SMOKE_IMAGE:-ubuntu:20.04}"
commands=(lnproxy-client lnproxy-init lnproxy-node lnproxy-probe)

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required for the Linux compatibility smoke test" >&2
	exit 1
fi

dist="$(cd "$dist" && pwd)"
if ! docker info >/dev/null 2>&1; then
	echo "docker daemon is unavailable for the Linux compatibility smoke test" >&2
	exit 1
fi

for cmd in "${commands[@]}"; do
	binary="/dist/linux-amd64/$cmd"
	set +e
	output="$(docker run --rm --network none \
		-v "$dist:/dist:ro" "$image" \
		/bin/sh -c "$binary --help 2>&1")"
	status=$?
	set -e

	if [[ $status -gt 1 ]]; then
		echo "$cmd failed to start in $image (exit $status)" >&2
		printf '%s\n' "$output" >&2
		exit 1
	fi
	if [[ "$output" == *"GLIBC_"* || "$output" == *"not found"* ]]; then
		echo "$cmd failed the Linux compatibility smoke test" >&2
		printf '%s\n' "$output" >&2
		exit 1
	fi
	printf '%s: startup smoke test passed (exit %d)\n' "$cmd" "$status"
done
