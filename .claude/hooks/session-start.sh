#!/bin/bash
# SessionStart hook for Claude Code cloud sessions (Linux containers).
#
# Installs the .NET 10 SDK from the Ubuntu archive, enables Windows targeting so the
# WPF project restores and builds on Linux, and restores both projects. It never runs
# the application and never produces release artifacts.
#
# Only the build-side gates can run on Linux. The runtime gates need Windows, so the
# session is told to record them as not run (AGENTS.md section 3).
set -euo pipefail

# Local sessions keep their own Windows toolchain.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

fail() {
  echo "PC_BLACK_BOX_CLOUD_SETUP failed: $*" >&2
  exit 1
}

# EnableWindowsTargeting lets the SDK resolve the Windows Desktop targeting pack on Linux.
# Telemetry stays off: nothing leaves the session that the work did not ask for.
export EnableWindowsTargeting=true DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  for name in EnableWindowsTargeting DOTNET_CLI_TELEMETRY_OPTOUT DOTNET_NOLOGO; do
    line="export $name=${!name}"
    grep -qxF "$line" "$CLAUDE_ENV_FILE" 2>/dev/null || echo "$line" >> "$CLAUDE_ENV_FILE"
  done
fi

# The Ubuntu package is signed by the archive, receives security updates, and ships the
# Windows Desktop SDK that compiles the XAML. The SDK list is captured first: with
# pipefail, grep -q exiting early would fail the pipe on a multi-SDK image.
installed_sdks="$(dotnet --list-sdks 2>/dev/null || true)"
if ! grep -q '^10\.' <<< "$installed_sdks"; then
  command -v apt-get >/dev/null || fail "no .NET 10 SDK and no apt-get to install one"
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update >&2 || fail "apt-get update"
  apt-get -qq install -y --no-install-recommends dotnet-sdk-10.0 >&2 \
    || fail "apt-get install dotnet-sdk-10.0"
fi

# A global.json pin is honored, never bypassed.
sdk_version="$(dotnet --version 2>/dev/null)" \
  || fail "dotnet --version failed in the repository (installed: $(dotnet --list-sdks | cut -d' ' -f1 | paste -sd' ' -))." \
    "If global.json pins a band other than 10.0.1xx, the only one the Ubuntu archive ships," \
    "this hook needs a step that installs the official SDK, and the environment's network" \
    "policy must allow builds.dotnet.microsoft.com."

for project in Destiny2BlackBox.csproj tests/RuntimeBoundaryProbe/RuntimeBoundaryProbe.csproj; do
  dotnet restore "$project" -v:q >&2 || fail "dotnet restore $project"
done

cat <<EOF
PC_BLACK_BOX_CLOUD_SETUP sdk=$sdk_version windows-targeting=true restore=ok
Runnable in this Linux session: dotnet build -c Release (analyzers, warnings as errors), dotnet format --verify-no-changes, dotnet list package --vulnerable --include-transitive, git diff --check.
Not runnable here: --security-status and --self-test (no Windows Desktop runtime exists for Linux) and tests/Test-RuntimeBoundaries.ps1 (Windows GUI). Record them as not run, never as passed.
EOF
