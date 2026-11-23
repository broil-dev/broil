#!/usr/bin/env bash
# Build from an isolated, source-carried tools/image-analyzer directory.
set -euo pipefail
analyzer_output="${1:?usage: build-analyzer.sh ABSOLUTE_OUTPUT}"
case "$analyzer_output" in /*) ;; *) echo 'output must be absolute' >&2; exit 2 ;; esac
export GOTOOLCHAIN=local GOENV=off GOWORK=off CGO_ENABLED=0 GOPROXY=off GOSUMDB=off
[[ "$(go version)" == 'go version go1.27.1 linux/amd64' ]] || { echo 'unsupported compiler' >&2; exit 2; }
go build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o "$analyzer_output" .
chmod 0700 -- "$analyzer_output"
