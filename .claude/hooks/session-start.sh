#!/bin/bash
# Prepares a Claude Code cloud session (Linux) to build and lint PC Black Box.
# The product targets Windows; EnableWindowsTargeting lets the Linux SDK compile it, but the
# self-test and runtime-boundary gates still need Windows and must be reported as not run.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

DOTNET_ROOT="$HOME/.dotnet"
CHANNEL="10.0"

if ! "$DOTNET_ROOT/dotnet" --list-sdks 2>/dev/null | grep -q "^${CHANNEL}\."; then
  installer="$(mktemp -d)/dotnet-install.sh"
  curl -sSfL --retry 4 -o "$installer" https://dot.net/v1/dotnet-install.sh
  bash "$installer" --channel "$CHANNEL" --install-dir "$DOTNET_ROOT" --no-path
  rm -f "$installer"
fi

export DOTNET_ROOT PATH="$DOTNET_ROOT:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 EnableWindowsTargeting=true

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo "export DOTNET_ROOT=\"$DOTNET_ROOT\""
    echo "export PATH=\"$DOTNET_ROOT:\$PATH\""
    echo "export DOTNET_CLI_TELEMETRY_OPTOUT=1"
    echo "export DOTNET_NOLOGO=1"
    echo "export EnableWindowsTargeting=true"
  } >> "$CLAUDE_ENV_FILE"
fi

dotnet restore "$CLAUDE_PROJECT_DIR/Destiny2BlackBox.csproj"
