#!/bin/bash
set -e

echo "Building sshproxy..."

go mod tidy
go build -o sshproxy .

echo "Build complete: ./sshproxy"
