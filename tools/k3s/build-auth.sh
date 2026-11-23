#!/usr/bin/env bash
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
# Compile only the unmodified, verified candidate supplied by the proof driver.
set -euo pipefail
auth_source="${1:?usage: build-auth.sh ABSOLUTE_SOURCE ABSOLUTE_OUTPUT}"
auth_output="${2:?usage: build-auth.sh ABSOLUTE_SOURCE ABSOLUTE_OUTPUT}"
case "$auth_source:$auth_output" in /*:/*) ;; *) exit 2 ;; esac
export GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOENV=off GOWORK=off
export CGO_ENABLED=0 GOPROXY=off GOSUMDB=off
[[ "$(go version)" == 'go version go1.27.1 linux/amd64' ]] || exit 2
cd -- "$auth_source"
go build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o "$auth_output" .
chmod 0700 -- "$auth_output"
