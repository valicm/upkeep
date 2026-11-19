#!/bin/sh
# Builds the static upkeep binaries for every platform upkeep runs on, into dist/.
#
#   scripts/build.sh            version from "git describe"
#   scripts/build.sh 0.1.0      version given
#   VERSION=0.1.0 scripts/build.sh
#
# One binary per platform, no C library needed (CGO_ENABLED=0), paths of the build machine
# left out (-trimpath). The same binary is agent and server.
set -eu

cd "$(dirname "$0")/.."

version=${1:-${VERSION:-}}
if [ -z "$version" ]; then
	version=$(git describe --tags --always --dirty 2>/dev/null || true)
fi
version=${version:-dev}
version=${version#v}

# GOOS/GOARCH/GOARM and the name the file gets.
targets="
linux/amd64//linux-amd64
linux/arm64//linux-arm64
linux/arm/7/linux-armv7
freebsd/amd64//freebsd-amd64
"

mkdir -p dist
built=""
for target in $targets; do
	goos=$(echo "$target" | cut -d/ -f1)
	goarch=$(echo "$target" | cut -d/ -f2)
	goarm=$(echo "$target" | cut -d/ -f3)
	name=upkeep-$(echo "$target" | cut -d/ -f4)
	echo "building dist/$name ($version)" >&2
	CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch GOARM=$goarm \
		go build -trimpath \
		-ldflags "-s -w -X github.com/valicm/upkeep/internal/version.Version=$version" \
		-o "dist/$name" ./cmd/upkeep
	built="$built $name"
done

cd dist
# shellcheck disable=SC2086
sha256sum $built >SHA256SUMS
echo
echo "upkeep $version"
for name in $built; do
	printf '%-24s %10s bytes  %5s MiB\n' "$name" "$(wc -c <"$name" | tr -d ' ')" "$(du -m "$name" | cut -f1)"
done
