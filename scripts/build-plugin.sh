#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$ROOT/dist"

docker run --rm \
  --mount "type=bind,source=$ROOT,target=/src" \
  --workdir /src \
  golang:1.26-bookworm \
  sh -c 'gofmt -w . && go test ./... && go build -trimpath -buildmode=c-shared -o dist/auth-inspect-linux-amd64.so .'
