$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
New-Item -ItemType Directory -Path (Join-Path $root "dist") -Force | Out-Null

docker run --rm `
  --mount "type=bind,source=$root,target=/src" `
  --workdir /src `
  golang:1.26-bookworm `
  sh -c "gofmt -w . && go test ./... && go build -trimpath -buildmode=c-shared -o dist/auth-inspect-linux-amd64.so ."
