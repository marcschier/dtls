#!/usr/bin/env bash
# Linux build + test verification via WSL. Builds the solution and runs all test projects
# using the WSL-local .NET SDK. Run from anywhere; resolves the repo root from this script.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export DOTNET_ROOT="$HOME/.dotnet"
export PATH="$HOME/.dotnet:$PATH"
export DOTNET_NOLOGO=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
cd "$REPO_ROOT"

. /etc/os-release
echo "== dotnet $(dotnet --version) on ${PRETTY_NAME} =="

dotnet build Dtls.slnx -c Release "$@"
# The WSL SDK bundles the net10 runtime only; run tests on net10.0 (net8 is covered on
# Windows). The build above still compiles every target framework.
dotnet test tests/Dtls.UnitTests/Dtls.UnitTests.csproj -c Release -f net10.0 --no-build
dotnet test tests/Dtls.IntegrationTests/Dtls.IntegrationTests.csproj -c Release -f net10.0 --no-build
dotnet test tests/Dtls.Interop.Tests/Dtls.Interop.Tests.csproj -c Release --no-build
echo "== WSL verification passed =="
