#!/usr/bin/env bash

set -e
set -x

glide --home /tmp --no-color install
go test $(go list ./... | grep -v /vendor/)
go build -o $1
