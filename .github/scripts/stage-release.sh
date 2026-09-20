#!/usr/bin/env bash
set -euo pipefail

version="${1:?version is required}"
dist="${DIST_DIR:-dist}"
commands=(lnproxy-client lnproxy-init lnproxy-node lnproxy-probe)

rm -rf "$dist"
mkdir -p "$dist/linux-amd64" "$dist/windows-amd64" "$dist/assets"

for cmd in "${commands[@]}"; do
	go build -buildvcs=false -trimpath -o "$dist/linux-amd64/$cmd" "./cmd/$cmd"
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go build -buildvcs=false -trimpath -o "$dist/windows-amd64/$cmd.exe" "./cmd/$cmd"

	cp "$dist/linux-amd64/$cmd" "$dist/assets/${cmd}-${version}"
	cp "$dist/windows-amd64/$cmd.exe" "$dist/assets/${cmd}-${version}.exe"
done

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	go build -buildvcs=false -trimpath -ldflags=-H=windowsgui \
	-o "$dist/windows-amd64/lnproxy-windows-server.exe" \
	./cmd/lnproxy-windows-server
cp "$dist/windows-amd64/lnproxy-windows-server.exe" \
	"$dist/assets/lnproxy-windows-server-${version}.exe"

render_readme() {
	local source="$1"
	local destination="$2"
	local heading="$3"
	awk -v heading="$heading" '
		NR == 1 && $0 == "# lnproxy" {
			print heading
			next
		}
		{ print }
	' "$source" >"$destination"
}

render_readme README.md "$dist/README.md" "# lnproxy ${version}"
render_readme README.zh-CN.md "$dist/README.zh-CN.md" "# lnproxy ${version}（简体中文）"

(
	cd "$dist"
	zip -qr "lnproxy-${version}-amd64.zip" \
		linux-amd64 windows-amd64 README.md README.zh-CN.md
)

printf 'archive=%s\n' "$dist/lnproxy-${version}-amd64.zip"
printf 'assets=%s\n' "$dist/assets"
