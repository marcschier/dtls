#!/usr/bin/env bash
# Runs the WSL-local .NET SDK (installed under ~/.dotnet) for Linux builds and tests.
# Usage: eng/wsl-dotnet.sh <dotnet args...>   e.g. eng/wsl-dotnet.sh build Dtls.slnx -c Release
set -euo pipefail
export DOTNET_ROOT="$HOME/.dotnet"
export PATH="$HOME/.dotnet:$PATH"
export DOTNET_NOLOGO=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
exec dotnet "$@"
