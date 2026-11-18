#!/usr/bin/env bash
# Binary Upload Tracker launcher
# Requires root privileges for tcpdump packet capture

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root (required for tcpdump)." >&2
  echo "" >&2
  echo "Usage:" >&2
  echo "  sudo $0 [--interface <iface>]" >&2
  echo "" >&2
  echo "Default interface: en0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec bun run "${SCRIPT_DIR}/server.ts" "$@"