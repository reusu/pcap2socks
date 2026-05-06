#!/bin/sh
#
# Build pcap2socks. CGO is required (libpcap on macOS/Linux, Npcap SDK on Windows).
#
# Native build (default):
#   ./build.sh
#
# Cross-compile (needs the matching C cross-toolchain):
#   GOOS=linux   GOARCH=amd64 CC=x86_64-linux-gnu-gcc          ./build.sh
#   GOOS=linux   GOARCH=arm64 CC=aarch64-linux-gnu-gcc         ./build.sh
#   GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc        ./build.sh
#

set -e

PROJECT_NAME="pcap2socks"
OUTPUT_DIR="build"

GOOS=${GOOS:-$(go env GOOS)}
GOARCH=${GOARCH:-$(go env GOARCH)}
CGO_ENABLED=${CGO_ENABLED:-1}

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS="-s -w"
LDFLAGS="${LDFLAGS} -X 'main.version=${VERSION}'"
LDFLAGS="${LDFLAGS} -X 'main.commit=${COMMIT}'"
LDFLAGS="${LDFLAGS} -X 'main.buildDate=${BUILD_DATE}'"

OUTPUT_NAME="${PROJECT_NAME}_${GOOS}_${GOARCH}"
[ "$GOOS" = "windows" ] && OUTPUT_NAME="${OUTPUT_NAME}.exe"

mkdir -p "${OUTPUT_DIR}"

echo "Building ${OUTPUT_NAME} (CGO=${CGO_ENABLED}, version=${VERSION})"
env CGO_ENABLED=${CGO_ENABLED} GOOS=${GOOS} GOARCH=${GOARCH} \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${OUTPUT_DIR}/${OUTPUT_NAME}" .

echo "Done: ${OUTPUT_DIR}/${OUTPUT_NAME}"
ls -lh "${OUTPUT_DIR}/${OUTPUT_NAME}"
